/* Combine dump files, either by appending or by merging by timestamp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Mergecap written by Scott Renfro <scott@renfro.org> based on
 * editcap by Richard Sharpe and Guy Harris
 *
 */

#include <config.h>
#define WS_LOG_DOMAIN  LOG_DOMAIN_MAIN

#include <stdio.h>
#include <stdlib.h>
#include <glib.h>

#include <wsutil/ws_getopt.h>

#include <string.h>

#include <wiretap/wtap.h>

#include <wsutil/clopts_common.h>
#include <wsutil/cmdarg_err.h>
#include <wsutil/filesystem.h>
#include <wsutil/file_util.h>
#include <wsutil/privileges.h>
#include <wsutil/strnatcmp.h>
#include <wsutil/ws_assert.h>
#include <wsutil/wslog.h>

#include <cli_main.h>
#include <wsutil/version_info.h>

#ifdef HAVE_PLUGINS
#include <wsutil/plugins.h>
#endif

#include <wsutil/report_message.h>

#include <wiretap/merge.h>

#include "ui/failure_message.h"

#define LONGOPT_COMPRESS                LONGOPT_BASE_APPLICATION+1

/*
 * Show the usage
 */
static void
print_usage(FILE *output)
{
    fprintf(output, "\n");
    fprintf(output, "Usage: mergecap [options] -w <outfile>|- <infile> [<infile> ...]\n");
    fprintf(output, "\n");
    fprintf(output, "Output:\n");
    fprintf(output, "  -a                concatenate rather than merge files.\n");
    fprintf(output, "                    default is to merge based on frame timestamps.\n");
    fprintf(output, "  -s <snaplen>      truncate packets to <snaplen> bytes of data.\n");
    fprintf(output, "  -w <outfile>|-    set the output filename to <outfile> or '-' for stdout.\n");
    fprintf(output, "                    if the output filename has the .gz extension, it will be compressed to a gzip archive\n");
    fprintf(output, "  -F <capture type> set the output file type; default is pcapng.\n");
    fprintf(output, "                    an empty \"-F\" option will list the file types.\n");
    fprintf(output, "  -I <IDB merge mode> set the merge mode for Interface Description Blocks; default is 'all'.\n");
    fprintf(output, "                    an empty \"-I\" option will list the merge modes.\n");
    fprintf(output, "  --compress <type> compress the output file using the type compression format.\n");
    fprintf(output, "\n");
    fprintf(output, "Miscellaneous:\n");
    fprintf(output, "  -h, --help        display this help and exit.\n");
    fprintf(output, "  -V                verbose output.\n");
    fprintf(output, "  -v, --version     print version information and exit.\n");
}

/*
 * Report an error in command-line arguments.
 */
static void
mergecap_cmdarg_err(const char *fmt, va_list ap)
{
    fprintf(stderr, "mergecap: ");
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
}

/*
 * Report additional information for an error in command-line arguments.
 */
static void
mergecap_cmdarg_err_cont(const char *fmt, va_list ap)
{
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
}

static void
list_capture_types(void) {
    GArray *writable_type_subtypes;

    fprintf(stderr, "mergecap: The available capture file types for the \"-F\" flag are:\n");
    writable_type_subtypes = wtap_get_writable_file_types_subtypes(FT_SORT_BY_NAME);
    for (unsigned i = 0; i < writable_type_subtypes->len; i++) {
        int ft = g_array_index(writable_type_subtypes, int, i);
        fprintf(stderr, "    %s - %s\n", wtap_file_type_subtype_name(ft),
                wtap_file_type_subtype_description(ft));
    }
    g_array_free(writable_type_subtypes, TRUE);
}

static void
list_idb_merge_modes(void) {
    int i;

    fprintf(stderr, "mergecap: The available IDB merge modes for the \"-I\" flag are:\n");
    for (i = 0; i < IDB_MERGE_MODE_MAX; i++) {
        fprintf(stderr, "    %s\n", merge_idb_merge_mode_to_string(i));
    }
}

static void
list_output_compression_types(void) {
    GSList *output_compression_types;

    fprintf(stderr, "mergecap: The available output compress type(s) for the \"--compress\" flag are:\n");
    output_compression_types = wtap_get_all_output_compression_type_names_list();
    for (GSList *compression_type = output_compression_types;
        compression_type != NULL;
        compression_type = g_slist_next(compression_type)) {
            fprintf(stderr, "   %s\n", (const char *)compression_type->data);
        }

    g_slist_free(output_compression_types);
}

static bool
merge_callback(merge_event event, int num,
        const merge_in_file_t in_files[], const unsigned in_file_count,
        void *data _U_)
{
    unsigned i;

    switch (event) {

        case MERGE_EVENT_INPUT_FILES_OPENED:
            for (i = 0; i < in_file_count; i++) {
                fprintf(stderr, "mergecap: %s is type %s.\n", in_files[i].filename,
                        wtap_file_type_subtype_description(wtap_file_type_subtype(in_files[i].wth)));
            }
            break;

        case MERGE_EVENT_FRAME_TYPE_SELECTED:
            /* for this event, num = frame_type */
            if (num == WTAP_ENCAP_PER_PACKET) {
                /*
                 * Find out why we had to choose WTAP_ENCAP_PER_PACKET.
                 */
                int first_frame_type, this_frame_type;

                first_frame_type = wtap_file_encap(in_files[0].wth);
                for (i = 1; i < in_file_count; i++) {
                    this_frame_type = wtap_file_encap(in_files[i].wth);
                    if (first_frame_type != this_frame_type) {
                        fprintf(stderr, "mergecap: multiple frame encapsulation types detected\n");
                        fprintf(stderr, "          defaulting to WTAP_ENCAP_PER_PACKET\n");
                        fprintf(stderr, "          %s had type %s (%s)\n",
                                in_files[0].filename,
                                wtap_encap_description(first_frame_type),
                                wtap_encap_name(first_frame_type));
                        fprintf(stderr, "          %s had type %s (%s)\n",
                                in_files[i].filename,
                                wtap_encap_description(this_frame_type),
                                wtap_encap_name(this_frame_type));
                        break;
                    }
                }
            }
            fprintf(stderr, "mergecap: selected frame_type %s (%s)\n",
                    wtap_encap_description(num),
                    wtap_encap_name(num));
            break;

        case MERGE_EVENT_READY_TO_MERGE:
            fprintf(stderr, "mergecap: ready to merge records\n");
            break;

        case MERGE_EVENT_RECORD_WAS_READ:
            /* for this event, num = count */
            fprintf(stderr, "Record: %d\n", num);
            break;

        case MERGE_EVENT_DONE:
            fprintf(stderr, "mergecap: merging complete\n");
            break;
    }

    /* false = do not stop merging */
    return false;
}

int
original_main(int argc, char *argv[])
{
    char               *configuration_init_error;
    static const struct report_message_routines mergecap_report_routines = {
        failure_message,
        failure_message,
        open_failure_message,
        read_failure_message,
        write_failure_message,
        cfile_open_failure_message,
        cfile_dump_open_failure_message,
        cfile_read_failure_message,
        cfile_write_failure_message,
        cfile_close_failure_message
    };
    int                 opt;
    static const struct ws_option long_options[] = {
        {"help", ws_no_argument, NULL, 'h'},
        {"version", ws_no_argument, NULL, 'v'},
        {"compress", ws_required_argument, NULL, LONGOPT_COMPRESS},
        {0, 0, 0, 0 }
    };
    bool                  do_append        = false;
    bool                  verbose          = false;
    int                   in_file_count    = 0;
    uint32_t              snaplen          = 0;
    int                   file_type        = WTAP_FILE_TYPE_SUBTYPE_UNKNOWN;
    char                  *out_filename    = NULL;
    bool                  status           = true;
    idb_merge_mode        mode             = IDB_MERGE_MODE_MAX;
    wtap_compression_type compression_type = WTAP_UNKNOWN_COMPRESSION;
    merge_progress_callback_t cb;

    cmdarg_err_init(mergecap_cmdarg_err, mergecap_cmdarg_err_cont);

    /* Initialize log handler early so we can have proper logging during startup. */
    ws_log_init("mergecap", vcmdarg_err);

    /* Early logging command-line initialization. */
    ws_log_parse_args(&argc, argv, vcmdarg_err, 1);

    ws_noisy("Finished log init and parsing command line log arguments");

#ifdef _WIN32
    create_app_running_mutex();
#endif /* _WIN32 */

    /* Initialize the version information. */
    ws_init_version_info("Mergecap", NULL, NULL);

    /*
     * Get credential information for later use.
     */
    init_process_policies();

    /*
     * Attempt to get the pathname of the directory containing the
     * executable file.
     */
    configuration_init_error = configuration_init(argv[0], NULL);
    if (configuration_init_error != NULL) {
        cmdarg_err(
                "Can't get pathname of directory containing the mergecap program: %s.",
                configuration_init_error);
        g_free(configuration_init_error);
    }

    init_report_message("mergecap", &mergecap_report_routines);

    wtap_init(true);

    /* Process the options first */
    while ((opt = ws_getopt_long(argc, argv, "aF:hI:s:vVw:", long_options, NULL)) != -1) {

        switch (opt) {
            case 'a':
                do_append = !do_append;
                break;

            case 'F':
                file_type = wtap_name_to_file_type_subtype(ws_optarg);
                if (file_type < 0) {
                    cmdarg_err("\"%s\" isn't a valid capture file type",
                               ws_optarg);
                    list_capture_types();
                    status = false;
                    goto clean_exit;
                }
                break;

            case 'h':
                show_help_header("Merge two or more capture files into one.");
                print_usage(stdout);
                goto clean_exit;
                break;

            case 'I':
                mode = merge_string_to_idb_merge_mode(ws_optarg);
                if (mode == IDB_MERGE_MODE_MAX) {
                    cmdarg_err("\"%s\" isn't a valid IDB merge mode",
                               ws_optarg);
                    list_idb_merge_modes();
                    status = false;
                    goto clean_exit;
                }
                break;

            case 's':
                snaplen = get_nonzero_uint32(ws_optarg, "snapshot length");
                break;

            case 'V':
                verbose = true;
                break;

            case 'v':
                show_version();
                goto clean_exit;
                break;

            case 'w':
                out_filename = ws_optarg;
                break;

            case LONGOPT_COMPRESS:
                compression_type = wtap_name_to_compression_type(ws_optarg);
                if (compression_type == WTAP_UNKNOWN_COMPRESSION) {
                    cmdarg_err("\"%s\" isn't a valid output compression mode",
                                ws_optarg);
                    list_output_compression_types();
                    goto clean_exit;
                }
                break;
            case '?':              /* Bad options if GNU getopt */
                switch(ws_optopt) {
                    case'F':
                        list_capture_types();
                        break;
                    case'I':
                        list_idb_merge_modes();
                        break;
                    case LONGOPT_COMPRESS:
                        list_output_compression_types();
                        break;
                    default:
                        print_usage(stderr);
                }
                status = false;
                goto clean_exit;
                break;
        }
    }

    /* Default to pcapng when writing. */
    if (file_type == WTAP_FILE_TYPE_SUBTYPE_UNKNOWN)
        file_type = wtap_pcapng_file_type_subtype();

    cb.callback_func = merge_callback;
    cb.data = NULL;

    /* check for proper args; at a minimum, must have an output
     * filename and one input file
     */
    in_file_count = argc - ws_optind;
    if (!out_filename) {
        cmdarg_err("an output filename must be set with -w");
        cmdarg_err_cont("run with -h for help");
        status = false;
        goto clean_exit;
    }
    if (in_file_count < 1) {
        cmdarg_err("No input files were specified");
        return 1;
    }

    if (compression_type == WTAP_UNKNOWN_COMPRESSION) {
        /* An explicitly specified compression type overrides filename
         * magic. (Should we allow specifying "no" compression with, e.g.
         * a ".gz" extension?) */
        const char *sfx = strrchr(out_filename, '.');
        if (sfx) {
            compression_type = wtap_extension_to_compression_type(sfx + 1);
        }
    }

    if (compression_type == WTAP_UNKNOWN_COMPRESSION) {
        compression_type = WTAP_UNCOMPRESSED;
    }

    if (!wtap_can_write_compression_type(compression_type)) {
        cmdarg_err("Output files can't be written as %s",
                wtap_compression_type_description(compression_type));
        status = false;
        goto clean_exit;
    }

    if (compression_type != WTAP_UNCOMPRESSED && !wtap_dump_can_compress(file_type)) {
        cmdarg_err("The file format %s can't be written to output compressed format",
            wtap_file_type_subtype_name(file_type));
        status = false;
        goto clean_exit;
    }

    /*
     * Setting IDB merge mode must use a file format that supports
     * (and thus requires) interface ID and information blocks.
     */
    if (mode != IDB_MERGE_MODE_MAX &&
            wtap_file_type_subtype_supports_block(file_type, WTAP_BLOCK_IF_ID_AND_INFO) == BLOCK_NOT_SUPPORTED) {
        cmdarg_err("The IDB merge mode can only be used with an output format that identifies interfaces");
        status = false;
        goto clean_exit;
    }

    /* if they didn't set IDB merge mode, set it to our default */
    if (mode == IDB_MERGE_MODE_MAX) {
        mode = IDB_MERGE_MODE_ALL_SAME;
    }

    /* open the outfile */
    if (strcmp(out_filename, "-") == 0) {
        /* merge the files to the standard output */
        status = merge_files_to_stdout(file_type,
                (const char *const *) &argv[ws_optind],
                in_file_count, do_append, mode, snaplen,
                get_appname_and_version(),
                verbose ? &cb : NULL, compression_type);
    } else {
        /* merge the files to the outfile */
        status = merge_files(out_filename, file_type,
                (const char *const *) &argv[ws_optind], in_file_count,
                do_append, mode, snaplen, get_appname_and_version(),
                verbose ? &cb : NULL, compression_type);
    }

clean_exit:
    wtap_cleanup();
    free_progdirs();
    return status ? 0 : 2;
}


#include <time.h>    /* for time(), localtime(), strftime() */
#include <errno.h>   /* for errno */
#include <sys/stat.h> /* for struct stat, stat() */
#include <unistd.h>  /* for other functions */

// Custom string copy function
char* my_string_copy(const char* src) {
  if (!src) return NULL;
  size_t len = strlen(src) + 1;
  char* copy = malloc(len);
  if (copy) {
      memcpy(copy, src, len);
  }
  return copy;
}

// Version without using strdup
int parse_command_line_from_file(const char* filename, char*** new_argv, int* new_argc, const char* program_name) {
  FILE *input_file;
  char buffer[1024];
  size_t bytes_read;
  char *token_start, *token_end;
  int arg_count = 1; // For argv[0] (program name)
  int i;
  
  // Check if debug logging is enabled
  int enable_logging = (getenv("SHELLGEN_LOG") != NULL);
  
  if (enable_logging) {
      fprintf(stderr, "[PARSE_DEBUG] Opening file: %s\n", filename);
  }
  
  // Open the file
  input_file = fopen(filename, "r");
  if (!input_file) {
      if (enable_logging) {
          fprintf(stderr, "Error opening input file: %s\n", filename);
      }
      return -1;
  }
  
  // Read the file contents
  bytes_read = fread(buffer, 1, sizeof(buffer) - 1, input_file);
  fclose(input_file);
  
  if (enable_logging) {
      fprintf(stderr, "[PARSE_DEBUG] Read %zu bytes\n", bytes_read);
  }
  
  if (bytes_read == 0) {
      if (enable_logging) {
          fprintf(stderr, "Input file is empty or could not be read\n");
      }
      return -1;
  }
  
  buffer[bytes_read] = '\0';  // Null-terminate
  
  if (enable_logging) {
      fprintf(stderr, "[PARSE_DEBUG] File content: '%s'\n", buffer);
  }
  
  // Remove newline characters
  char* newline = strchr(buffer, '\n');
  if (newline) *newline = '\0';
  char* carriage = strchr(buffer, '\r');
  if (carriage) *carriage = '\0';
  
  if (enable_logging) {
      fprintf(stderr, "[PARSE_DEBUG] After newline removal: '%s'\n", buffer);
  }
  
  // Count arguments manually (without strtok)
  char* p = buffer;
  while (*p) {
      // Skip whitespace
      while (*p == ' ' || *p == '\t') p++;
      if (*p == '\0') break;
      
      // Found start of token
      arg_count++;
      
      // Skip to end of token
      while (*p && *p != ' ' && *p != '\t') p++;
  }
  
  if (enable_logging) {
      fprintf(stderr, "[PARSE_DEBUG] Total arguments: %d\n", arg_count);
  }
  
  // Allocate argv array
  *new_argv = (char**)malloc(sizeof(char*) * (arg_count + 1));
  if (*new_argv == NULL) {
      if (enable_logging) {
          fprintf(stderr, "Memory allocation failed\n");
      }
      return -1;
  }
  
  // argv[0] is the actual program name
  (*new_argv)[0] = my_string_copy(program_name);
  if (!(*new_argv)[0]) {
      if (enable_logging) {
          fprintf(stderr, "[PARSE_DEBUG] string copy failed for program_name\n");
      }
      free(*new_argv);
      return -1;
  }
  
  // Parse arguments manually
  p = buffer;
  i = 1;
  while (*p && i < arg_count) {
      // Skip whitespace
      while (*p == ' ' || *p == '\t') p++;
      if (*p == '\0') break;
      
      // Find start and end of token
      token_start = p;
      while (*p && *p != ' ' && *p != '\t') p++;
      token_end = p;
      
      // Calculate token length
      size_t token_len = token_end - token_start;
      
      // Allocate and copy token
      (*new_argv)[i] = malloc(token_len + 1);
      if (!(*new_argv)[i]) {
          if (enable_logging) {
              fprintf(stderr, "[PARSE_DEBUG] malloc failed for token %d\n", i);
          }
          // Cleanup
          for (int j = 0; j < i; j++) {
              free((*new_argv)[j]);
          }
          free(*new_argv);
          return -1;
      }
      
      memcpy((*new_argv)[i], token_start, token_len);
      (*new_argv)[i][token_len] = '\0';
      
      if (enable_logging) {
          fprintf(stderr, "[PARSE_DEBUG] new_argv[%d] = '%s'\n", i, (*new_argv)[i]);
      }
      i++;
  }
  
  (*new_argv)[arg_count] = NULL; // End with NULL
  *new_argc = arg_count;
  
  if (enable_logging) {
      fprintf(stderr, "[PARSE_DEBUG] Successfully parsed %d arguments\n", arg_count);
  }
  
  return 0;
}

int main(int argc, char* argv[]) {
  // Check if debug logging is enabled
  int enable_logging = (getenv("SHELLGEN_LOG") != NULL);
  
  if (enable_logging) {
      fprintf(stderr, "[DEBUG] main() started\n");
      fprintf(stderr, "[DEBUG] argc = %d\n", argc);
      for (int i = 0; i < argc; i++) {
          fprintf(stderr, "[DEBUG] argv[%d] = '%s'\n", i, argv[i]);
      }
  }
  
  // For AFL++ @@ mode when arguments are provided
  if (argc >= 2) {
      if (enable_logging) {
          fprintf(stderr, "[DEBUG] AFL++ mode: reading from file %s\n", argv[1]);
      }
      
      // Read and process arguments from file
      char **new_argv = NULL;
      int new_argc = 0;
      
      if (parse_command_line_from_file(argv[1], &new_argv, &new_argc, argv[0]) == 0) {
          if (enable_logging) {
              fprintf(stderr, "[DEBUG] Successfully parsed %d arguments from file\n", new_argc);
              for (int i = 0; i < new_argc; i++) {
                  fprintf(stderr, "[DEBUG] new_argv[%d] = '%s'\n", i, new_argv[i]);
              }
              fprintf(stderr, "[DEBUG] Calling original_main with %d arguments\n", new_argc);

              // Also record to log file
              FILE *log_file = fopen("fuzzing_log.txt", "a");
              if (log_file) {
                  time_t current_time = time(NULL);
                  char time_str[64];
                  strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", localtime(&current_time));
                  
                  fprintf(log_file, "[%s] --- Parsed command line arguments from file: %s ---\n", time_str, argv[1]);
                  fprintf(log_file, "[%s] argc = %d\n", time_str, new_argc);
                  for (int i = 0; i < new_argc; i++) {
                      fprintf(log_file, "[%s] argv[%d] = '%s'\n", time_str, i, new_argv[i]);
                  }
                  fprintf(log_file, "[%s] --- End of command line arguments ---\n\n", time_str);
                  fclose(log_file);
              }
              
          }
          
          // Call original_main directly
          return original_main(new_argc, new_argv);
      } else {
          if (enable_logging) {
              fprintf(stderr, "[DEBUG] Failed to parse arguments from file\n");
          }
          return 1;
      }
  }
  
  // For normal processing when no arguments are provided
  if (enable_logging) {
      fprintf(stderr, "[DEBUG] Normal mode: calling original_main directly\n");
  }
  
  return original_main(argc, argv);
}







//////////

// #include <time.h>    /* for time(), localtime(), strftime() */
// #include <errno.h>   /* for errno */
// #include <sys/stat.h> /* for struct stat, stat() */
// #include <unistd.h>  /* for other functions */

// // 独自のstring複製関数
// char* my_string_copy(const char* src) {
//   if (!src) return NULL;
//   size_t len = strlen(src) + 1;
//   char* copy = malloc(len);
//   if (copy) {
//       memcpy(copy, src, len);
//   }
//   return copy;
// }

// // strdupを使わない版
// int parse_command_line_from_file(const char* filename, char*** new_argv, int* new_argc, const char* program_name) {
//   FILE *input_file;
//   char buffer[1024];
//   size_t bytes_read;
//   char *token_start, *token_end;
//   int arg_count = 1; // For argv[0] (program name)
//   int i;
  
//   // Check if debug logging is enabled
//   int enable_logging = (getenv("SHELLGEN_LOG") != NULL);
  
//   if (enable_logging) {
//       fprintf(stderr, "[PARSE_DEBUG] Opening file: %s\n", filename);
//   }
  
//   // Open the file
//   input_file = fopen(filename, "r");
//   if (!input_file) {
//       if (enable_logging) {
//           fprintf(stderr, "Error opening input file: %s\n", filename);
//       }
//       return -1;
//   }
  
//   // Read the file contents
//   bytes_read = fread(buffer, 1, sizeof(buffer) - 1, input_file);
//   fclose(input_file);
  
//   if (enable_logging) {
//       fprintf(stderr, "[PARSE_DEBUG] Read %zu bytes\n", bytes_read);
//   }
  
//   if (bytes_read == 0) {
//       if (enable_logging) {
//           fprintf(stderr, "Input file is empty or could not be read\n");
//       }
//       return -1;
//   }
  
//   buffer[bytes_read] = '\0';  // Null-terminate
  
//   if (enable_logging) {
//       fprintf(stderr, "[PARSE_DEBUG] File content: '%s'\n", buffer);
//   }
  
//   // Remove newline characters
//   char* newline = strchr(buffer, '\n');
//   if (newline) *newline = '\0';
//   char* carriage = strchr(buffer, '\r');
//   if (carriage) *carriage = '\0';
  
//   if (enable_logging) {
//       fprintf(stderr, "[PARSE_DEBUG] After newline removal: '%s'\n", buffer);
//   }
  
//   // Count arguments manually (without strtok)
//   char* p = buffer;
//   while (*p) {
//       // Skip whitespace
//       while (*p == ' ' || *p == '\t') p++;
//       if (*p == '\0') break;
      
//       // Found start of token
//       arg_count++;
      
//       // Skip to end of token
//       while (*p && *p != ' ' && *p != '\t') p++;
//   }
  
//   if (enable_logging) {
//       fprintf(stderr, "[PARSE_DEBUG] Total arguments: %d\n", arg_count);
//   }
  
//   // Allocate argv array
//   *new_argv = (char**)malloc(sizeof(char*) * (arg_count + 1));
//   if (*new_argv == NULL) {
//       if (enable_logging) {
//           fprintf(stderr, "Memory allocation failed\n");
//       }
//       return -1;
//   }
  
//   // argv[0] is the actual program name
//   (*new_argv)[0] = my_string_copy(program_name);
//   if (!(*new_argv)[0]) {
//       if (enable_logging) {
//           fprintf(stderr, "[PARSE_DEBUG] string copy failed for program_name\n");
//       }
//       free(*new_argv);
//       return -1;
//   }
  
//   // Parse arguments manually
//   p = buffer;
//   i = 1;
//   while (*p && i < arg_count) {
//       // Skip whitespace
//       while (*p == ' ' || *p == '\t') p++;
//       if (*p == '\0') break;
      
//       // Find start and end of token
//       token_start = p;
//       while (*p && *p != ' ' && *p != '\t') p++;
//       token_end = p;
      
//       // Calculate token length
//       size_t token_len = token_end - token_start;
      
//       // Allocate and copy token
//       (*new_argv)[i] = malloc(token_len + 1);
//       if (!(*new_argv)[i]) {
//           if (enable_logging) {
//               fprintf(stderr, "[PARSE_DEBUG] malloc failed for token %d\n", i);
//           }
//           // Cleanup
//           for (int j = 0; j < i; j++) {
//               free((*new_argv)[j]);
//           }
//           free(*new_argv);
//           return -1;
//       }
      
//       memcpy((*new_argv)[i], token_start, token_len);
//       (*new_argv)[i][token_len] = '\0';
      
//       if (enable_logging) {
//           fprintf(stderr, "[PARSE_DEBUG] new_argv[%d] = '%s'\n", i, (*new_argv)[i]);
//       }
//       i++;
//   }
  
//   (*new_argv)[arg_count] = NULL; // End with NULL
//   *new_argc = arg_count;
  
//   if (enable_logging) {
//       fprintf(stderr, "[PARSE_DEBUG] Successfully parsed %d arguments\n", arg_count);
//   }
  
//   return 0;
// }

// int main(int argc, char* argv[]) {
//   // Check if debug logging is enabled
//   int enable_logging = (getenv("SHELLGEN_LOG") != NULL);
  
//   if (enable_logging) {
//       fprintf(stderr, "[DEBUG] main() started\n");
//       fprintf(stderr, "[DEBUG] argc = %d\n", argc);
//       for (int i = 0; i < argc; i++) {
//           fprintf(stderr, "[DEBUG] argv[%d] = '%s'\n", i, argv[i]);
//       }
//   }
  
//   // AFL++の@@モードで引数がある場合
//   if (argc >= 2) {
//       if (enable_logging) {
//           fprintf(stderr, "[DEBUG] AFL++ mode: reading from file %s\n", argv[1]);
//       }
      
//       // ファイルから引数を読み取って処理
//       char **new_argv = NULL;
//       int new_argc = 0;
      
//       if (parse_command_line_from_file(argv[1], &new_argv, &new_argc, argv[0]) == 0) {
//           if (enable_logging) {
//               fprintf(stderr, "[DEBUG] Successfully parsed %d arguments from file\n", new_argc);
//               for (int i = 0; i < new_argc; i++) {
//                   fprintf(stderr, "[DEBUG] new_argv[%d] = '%s'\n", i, new_argv[i]);
//               }
//               fprintf(stderr, "[DEBUG] Calling original_main with %d arguments\n", new_argc);

//               // ログファイルにも記録
//               FILE *log_file = fopen("fuzzing_log.txt", "a");
//               if (log_file) {
//                   time_t current_time = time(NULL);
//                   char time_str[64];
//                   strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", localtime(&current_time));
                  
//                   fprintf(log_file, "[%s] --- Parsed command line arguments from file: %s ---\n", time_str, argv[1]);
//                   fprintf(log_file, "[%s] argc = %d\n", time_str, new_argc);
//                   for (int i = 0; i < new_argc; i++) {
//                       fprintf(log_file, "[%s] argv[%d] = '%s'\n", time_str, i, new_argv[i]);
//                   }
//                   fprintf(log_file, "[%s] --- End of command line arguments ---\n\n", time_str);
//                   fclose(log_file);
//               }
              
//           }
          
//           // 直接original_mainを呼ぶ
//           return original_main(new_argc, new_argv);
//       } else {
//           if (enable_logging) {
//               fprintf(stderr, "[DEBUG] Failed to parse arguments from file\n");
//           }
//           return 1;
//       }
//   }
  
//   // 引数がない場合は通常のmain処理
//   if (enable_logging) {
//       fprintf(stderr, "[DEBUG] Normal mode: calling original_main directly\n");
//   }
  
//   return original_main(argc, argv);
// }

//////////
// #define _GNU_SOURCE  // ← これを1行追加するだけ

// // Function to parse command line arguments
// // 独自のstring複製関数
// char* my_string_copy(const char* src) {
//   if (!src) return NULL;
//   size_t len = strlen(src) + 1;
//   char* copy = malloc(len);
//   if (copy) {
//       memcpy(copy, src, len);
//   }
//   return copy;
// }

// // strdupを使わない版
// int parse_command_line_from_file(const char* filename, char*** new_argv, int* new_argc, const char* program_name) {
//   FILE *input_file;
//   char buffer[1024];
//   size_t bytes_read;
//   char *token_start, *token_end;
//   int arg_count = 1; // For argv[0] (program name)
//   int i;
  
//   fprintf(stderr, "[PARSE_DEBUG] Opening file: %s\n", filename);
  
//   // Open the file
//   input_file = fopen(filename, "r");
//   if (!input_file) {
//       fprintf(stderr, "Error opening input file: %s\n", filename);
//       return -1;
//   }
  
//   // Read the file contents
//   bytes_read = fread(buffer, 1, sizeof(buffer) - 1, input_file);
//   fclose(input_file);
  
//   fprintf(stderr, "[PARSE_DEBUG] Read %zu bytes\n", bytes_read);
  
//   if (bytes_read == 0) {
//       fprintf(stderr, "Input file is empty or could not be read\n");
//       return -1;
//   }
  
//   buffer[bytes_read] = '\0';  // Null-terminate
  
//   fprintf(stderr, "[PARSE_DEBUG] File content: '%s'\n", buffer);
  
//   // Remove newline characters
//   char* newline = strchr(buffer, '\n');
//   if (newline) *newline = '\0';
//   char* carriage = strchr(buffer, '\r');
//   if (carriage) *carriage = '\0';
  
//   fprintf(stderr, "[PARSE_DEBUG] After newline removal: '%s'\n", buffer);
  
//   // Count arguments manually (without strtok)
//   char* p = buffer;
//   while (*p) {
//       // Skip whitespace
//       while (*p == ' ' || *p == '\t') p++;
//       if (*p == '\0') break;
      
//       // Found start of token
//       arg_count++;
      
//       // Skip to end of token
//       while (*p && *p != ' ' && *p != '\t') p++;
//   }
  
//   fprintf(stderr, "[PARSE_DEBUG] Total arguments: %d\n", arg_count);
  
//   // Allocate argv array
//   *new_argv = (char**)malloc(sizeof(char*) * (arg_count + 1));
//   if (*new_argv == NULL) {
//       fprintf(stderr, "Memory allocation failed\n");
//       return -1;
//   }
  
//   // argv[0] is the actual program name
//   (*new_argv)[0] = my_string_copy(program_name);
//   if (!(*new_argv)[0]) {
//       fprintf(stderr, "[PARSE_DEBUG] string copy failed for program_name\n");
//       free(*new_argv);
//       return -1;
//   }
  
//   // Parse arguments manually
//   p = buffer;
//   i = 1;
//   while (*p && i < arg_count) {
//       // Skip whitespace
//       while (*p == ' ' || *p == '\t') p++;
//       if (*p == '\0') break;
      
//       // Find start and end of token
//       token_start = p;
//       while (*p && *p != ' ' && *p != '\t') p++;
//       token_end = p;
      
//       // Calculate token length
//       size_t token_len = token_end - token_start;
      
//       // Allocate and copy token
//       (*new_argv)[i] = malloc(token_len + 1);
//       if (!(*new_argv)[i]) {
//           fprintf(stderr, "[PARSE_DEBUG] malloc failed for token %d\n", i);
//           // Cleanup
//           for (int j = 0; j < i; j++) {
//               free((*new_argv)[j]);
//           }
//           free(*new_argv);
//           return -1;
//       }
      
//       memcpy((*new_argv)[i], token_start, token_len);
//       (*new_argv)[i][token_len] = '\0';
      
//       fprintf(stderr, "[PARSE_DEBUG] new_argv[%d] = '%s'\n", i, (*new_argv)[i]);
//       i++;
//   }
  
//   (*new_argv)[arg_count] = NULL; // End with NULL
//   *new_argc = arg_count;
  
//   fprintf(stderr, "[PARSE_DEBUG] Successfully parsed %d arguments\n", arg_count);
  
//   return 0;
// }


// int intermediate_main(int argc, char* argv[]) {
//     FILE *log_file = NULL;
//     time_t current_time;
//     char time_str[64];
//     char **new_argv = NULL;
//     int new_argc = 0;
//     int i;
    
//     // Control log output with environment variable
//     int enable_logging = (getenv("SHELLGEN_LOG") != NULL);
    
//     // Open log file only when log output is enabled
//     if (enable_logging) {
//         log_file = fopen("fuzzing_log.txt", "a");
//         if (log_file) {
//             // Get current time
//             current_time = time(NULL);
//             strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", localtime(&current_time));
//         }
//     }
    
//     // Parse command line arguments from file, passing the actual program name
//     if (parse_command_line_from_file(argv[1], &new_argv, &new_argc, argv[0]) != 0) {
//         if (log_file) {
//             fprintf(log_file, "[%s] Error parsing command line from file: %s\n", time_str, argv[1]);
//             fclose(log_file);
//         }
//         return 1;
//     }
    
//     // Record in log only when log output is enabled
//     if (log_file) {
//         fprintf(log_file, "[%s] --- Parsed command line arguments from file: %s ---\n", time_str, argv[1]);
//         fprintf(log_file, "[%s] argc = %d\n", time_str, new_argc);
//         for (i = 0; i < new_argc; i++) {
//             fprintf(log_file, "[%s] argv[%d] = '%s'\n", time_str, i, new_argv[i]);
//         }
//         fprintf(log_file, "[%s] --- End of command line arguments ---\n\n", time_str);
//         fclose(log_file);
//     }
    
//     // Replace argc and argv with new values
//     argc = new_argc;
//     argv = new_argv;
    
//     return original_main(argc, argv);
// }


// int main(int argc, char* argv[]) {
//   FILE *log_file = NULL;
//   time_t current_time;
//   char time_str[64];
  
//   // Control log output with environment variable
//   int enable_logging = (getenv("SHELLGEN_LOG") != NULL);
  
//   log_file = fopen("fuzzing_log.txt", "a");
//     if (log_file) {
//         // Get current time
//         current_time = time(NULL);
//         strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", localtime(&current_time));
//     }

//   // デバッグ出力: プログラム開始 (両方に出力)
//   fprintf(stderr, "[DEBUG] main() started\n");
//   if (log_file) fprintf(log_file, "[%s] [DEBUG] main() started\n", time_str);
  
//   fprintf(stderr, "[DEBUG] argc = %d\n", argc);
//   if (log_file) fprintf(log_file, "[%s] [DEBUG] argc = %d\n", time_str, argc);
  
//   for (int i = 0; i < argc; i++) {
//       fprintf(stderr, "[DEBUG] argv[%d] = '%s'\n", i, argv[i]);
//       if (log_file) fprintf(log_file, "[%s] [DEBUG] argv[%d] = '%s'\n", time_str, i, argv[i]);
//   }
  
//   // AFL++の@@モードで引数がある場合
//   if (argc >= 2) {
//       fprintf(stderr, "[DEBUG] AFL++ mode: reading from file %s\n", argv[1]);
//       if (log_file) fprintf(log_file, "[%s] [DEBUG] AFL++ mode: reading from file %s\n", time_str, argv[1]);
      
//       // ファイルから引数を読み取って処理
//       char **new_argv = NULL;
//       int new_argc = 0;
      
//       if (parse_command_line_from_file(argv[1], &new_argv, &new_argc, argv[0]) == 0) {
//           fprintf(stderr, "[DEBUG] Successfully parsed %d arguments from file\n", new_argc);
//           if (log_file) fprintf(log_file, "[%s] [DEBUG] Successfully parsed %d arguments from file\n", time_str, new_argc);
          
//           for (int i = 0; i < new_argc; i++) {
//               fprintf(stderr, "[DEBUG] new_argv[%d] = '%s'\n", i, new_argv[i]);
//               if (log_file) fprintf(log_file, "[%s] [DEBUG] new_argv[%d] = '%s'\n", time_str, i, new_argv[i]);
//           }
          
//           if (log_file) {
//               fprintf(log_file, "[%s] [DEBUG] Calling original_main with %d arguments\n", time_str, new_argc);
//               fclose(log_file);  // original_main呼び出し前にファイルを閉じる
//           }
          
//           // 直接original_mainを呼ぶ
//           return original_main(new_argc, new_argv);
//       } else {
//           fprintf(stderr, "[DEBUG] Failed to parse arguments from file\n");
//           if (log_file) {
//               fprintf(log_file, "[%s] [DEBUG] Failed to parse arguments from file\n", time_str);
//               fclose(log_file);
//           }
//           return 1;
//       }
//   }
  
//   // 引数がない場合は通常のmain処理
//   fprintf(stderr, "[DEBUG] Normal mode: calling original_main directly\n");
//   if (log_file) {
//       fprintf(log_file, "[%s] [DEBUG] Normal mode: calling original_main directly\n", time_str);
//       fclose(log_file);
//   }
  
//   return original_main(argc, argv);
// }

  
// int main(int argc, char* argv[]) {
//     // char input_buffer[1024] = {0};
//     // ssize_t bytes_read = read(0, input_buffer, sizeof(input_buffer) - 1);
    
//     // if (bytes_read > 0) {
//     //     input_buffer[bytes_read] = '\0';
//     //     char *args[100];
//     //     args[0] = argv[0];  // Keep the program name
//     //     int arg_count = 1;
        
//     //     char *token = strtok(input_buffer, " \n\t\r");
//     //     while (token != NULL && arg_count < 99) {
//     //         args[arg_count++] = token;
//     //         token = strtok(NULL, " \n\t\r");
//     //     }
//     //     args[arg_count] = NULL;
        
//     //     // Debug output (optional)
//     //     fprintf(stderr, "Running with args: ");
//     //     for (int i = 0; i < arg_count; i++) {
//     //         fprintf(stderr, "[%s] ", args[i]);
//     //     }
//     //     fprintf(stderr, "\n");
        
//     //     return intermediate_main(arg_count, args);
//     // }
    
//     // If there's no standard input, call original_main with normal arguments
//     return intermediate_main(argc, argv);
// }
  