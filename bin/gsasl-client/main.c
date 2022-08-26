#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include <gsasl.h>
#include <arpa/inet.h>

static int8_t authenticate(char *buf, size_t buflen, size_t rem, Gsasl_session *session, int sockfd) {
    size_t bufsz = rem;

    // output data for gsasl_step64
    char *output = NULL;

    int rc;
    int sent = 0;
    size_t fresh;
    bool first = true;

    do {
        // ==============================
        // Receive data
        // ==============================

        // this is correct because if there is data left in the buffer at this stage it must be data from the last step,
        // so we did not check that data for newlines at all!
        size_t newline_idx = 0;

        // Skip receiving data the first time around, so initial data works.
        if (!first) {
            do {
                int recv_amt;
                char *slice = buf + bufsz;

                // receive into moving buffer window.
                // we skip checking for newlines before recv because there is no chance that a server responded with data
                // for more than one step at once. If we're on the last step and the server already knows the outcome it
                // will sent two lines, and we may get them in this recv call, but we could not have gotten those two
                // lines in a previous recv.
                if ((recv_amt = recv(sockfd, slice, buflen - bufsz, 0)) <= 0) {
                    if (recv_amt == 0) {
                        fprintf(stderr, "server closed connection unexpectedly\n");
                        return -2;
                    } else {
                        fprintf(stderr, "failed to send mechanism name: %s\n", strerror(errno));
                        return -2;
                    }
                }
                // Mark newly written buffer window as used
                bufsz += recv_amt;

                // check for newline, but only in the newly received part. newline_idx is carried over from the last recv
                // call where we didn't find a newline
                for (; newline_idx < bufsz; newline_idx++) {
                    if (buf[newline_idx] == '\n') {
                        break;
                    }
                }

                if (newline_idx >= buflen) {
                    fprintf(stderr, "exhausted receive buffer!");
                    return -4;
                }
            } while (newline_idx == bufsz);

            // Remaining data starts exactly one byte after the newline byte, no matter if \r\n or just \n.
            fresh = newline_idx + 1;
        }

        // ==============================
        // Fixup data (Newline to zero-terminal)
        // ==============================

        // Check for and handle \r\n — if we only received one byte there can't be a \r
        // Afterwards our valid input data will be buf[0..newline_idx]. As gsasl_step64 expected a zero-terminated
        // string we just overwrite the newline (or \r if a \r\n was sent) with \0.
        if (newline_idx >= 1 && '\r' == buf[newline_idx - 1]) {
            newline_idx--;
        }
        // Write Zero-terminal after valid data, replacing either the \n or \r if \r\n was sent.
        // newline_idx can be at worst 0 here so this is always correct
        buf[newline_idx] = '\0';

        // ==============================
        // Step mechanism
        // ==============================
        rc = gsasl_step64(session, buf, &output);

        // In case step returned an error, we immediately break out.
        if (rc != GSASL_OK && rc != GSASL_NEEDS_MORE) {
            break;
        }

        // ==============================
        // Finish input data
        // ==============================

        // memmove any remaining data after a newline to the front of buf. The fresh data is everything *after* the
        // newline so we take the window one byte after newline_idx;
        char *fresh_slice = buf + fresh;
        size_t slice_len = bufsz - fresh;
        memmove(buf, fresh_slice, slice_len);
        // The size of the buffer is now only the data we received.
        bufsz = slice_len;

        // ==============================
        // Send data
        // ==============================
        size_t outlen = 0;
        if (output != NULL) {
            outlen = strnlen(output, BUFSIZ);
        }
        // loop until we have sent all output (minus a newline)
        char *slice = output;
        while (outlen > 0) {
            if ((sent = send(sockfd, slice, outlen, 0)) <= 0) {
                if (sent == 0) {
                    fprintf(stderr, "server closed connection unexpectedly\n");
                    return -2;
                } else {
                    fprintf(stderr, "failed to send mechanism name: %s\n", strerror(errno));
                    return -2;
                }
            }
            slice = output + (size_t)sent;
            outlen -= (size_t)sent;
        }
        // We've sent everything before the while loop above, so we can free the output.
        gsasl_free(output);

        // Finally, sent a newline
        if ((sent = send(sockfd, "\n", 1, 0)) <= 0) {
            if (sent == 0) {
                fprintf(stderr, "server closed connection unexpectedly\n");
                return -2;
            } else {
                fprintf(stderr, "failed to send mechanism name: %s\n", strerror(errno));
                return -2;
            }
        }

        first = false;
    } while (rc == GSASL_NEEDS_MORE);

    if (rc != GSASL_OK) {
        fprintf(stderr, "SASL stepping failed (%s): %s\n", gsasl_strerror_name(rc), gsasl_strerror(rc));
        return -1;
    }

    size_t idx = 0;
    // Go over the *existing* buffer and if there's not a final full line we do another recv to receive the outcome
    // from the server.
    // If a server sent some last data and then immediately the outcome we may have gotten that in the recv call
    // that we issued to get the last step data. So we must check for that case before issuing another recv.
    for (; idx < bufsz; idx++) {
        if (buf[idx] == '\n') {
            break;
        }
    }

    // idx == bufsz means 'not found', idx == (bufsz - 1) would be newline is in last byte of buf
    while (idx == bufsz) {
        // Basically we haven't found a final newline and our recv buffer is full
        if (bufsz >= buflen) {
            fprintf(stderr, "exhausted receive buffer!");
            return -4;
        }

        size_t recv_amt;
        char *slice = buf + bufsz;
        // receive into moving buffer window
        if ((recv_amt = recv(sockfd, slice, buflen - bufsz, 0)) <= 0) {
            if (recv_amt == 0) {
                fprintf(stderr, "server closed connection unexpectedly\n");
                return -2;
            } else {
                fprintf(stderr, "failed to send mechanism name: %s\n", strerror(errno));
                return -2;
            }
        }

        // Include the newly received data in the buffer size
        bufsz += recv_amt;

        for (; idx < bufsz; idx++) {
            if (buf[idx] == '\n') {
                break;
            }
        }
    }

    // idx != bufsz so idx points at the index of the final newline

    // Check for and handle \r\n — if we only received one byte there can't be a \r
    if (idx >= 1 && '\r' == buf[idx - 1]) {
        idx--;
    }

    buf[idx] = '\0';

    // we have our final complete response line!
    if (bufsz >= 2 && 'O' == buf[0] && 'K' == buf[1]) {
        // Print the outcome line excluding the newline
        printf("Authentication was successful: %*s\n", (int) (idx - 1), buf);
    } else if (bufsz >= 3 && 'E' == buf[0] && 'R' == buf[1] && 'R' == buf[2]) {
        printf("Authentication failed: %*s\n", (int) (idx - 1), buf);
    }

    return 0;
}

static int8_t client(Gsasl *ctx, const char *const mechanism, int sockfd) {
    char buf[BUFSIZ];
    size_t bufsz = 0;
    size_t idx = 0;
    do {
        // Basically we haven't found a final newline and our recv buffer is full. Can't be hit on the first loop,
        // must fail on a subsequent one.
        if (bufsz >= sizeof(buf)) {
            fprintf(stderr, "exhausted receive buffer!");
            return -4;
        }

        size_t recv_amt;
        char *slice = buf + bufsz;
        // receive into moving buffer window
        if ((recv_amt = recv(sockfd, slice, sizeof(buf) - bufsz, 0)) <= 0) {
            if (recv_amt == 0) {
                fprintf(stderr, "server closed connection unexpectedly\n");
                return -2;
            } else {
                fprintf(stderr, "failed to send mechanism name: %s\n", strerror(errno));
                return -2;
            }
        }

        // Include the newly received data in the buffer size
        bufsz += recv_amt;

        for (; idx < bufsz; idx++) {
            if (buf[idx] == '\n') {
                break;
            }
        }
        // idx == bufsz means 'not found', idx == (bufsz - 1) would be newline is in last byte of buf
    } while (idx == bufsz);

    // Fresh data starts after the newline
    size_t fresh = idx+1;
    // Move idx one back if the newline is \r\n
    if (idx >= 1 && buf[idx-1] == '\r') {
        idx--;
    }
    // idx is at worst 0 here, so this is always correct.
    buf[idx] = '\0';

    printf("Available mechanisms: %*s\n", (int)idx, buf);
    const char *suggestion = gsasl_client_suggest_mechanism(ctx, buf);
    printf("Suggested mechanism: %s\n", suggestion);

    size_t mech_len = strnlen(mechanism, 30);
    char* avail;
    for (avail = strtok(buf, " "); avail != NULL; avail = strtok(NULL, " ")) {
        if (strncmp(mechanism, avail, mech_len) == 0) {
            break;
        }
    }
    if (avail == NULL) {
        fprintf(stderr, "server does not support the wanted mechanism %s\n", mechanism);
        return -1;
    }
    printf("Chosen mechanism: %s\n", mechanism);

    size_t len = strnlen(mechanism, 30);
    size_t sent;
    if ((sent = send(sockfd, mechanism, len, 0)) <= 0) {
        if (sent == 0) {
            fprintf(stderr, "server closed connection unexpectedly\n");
            return -2;
        } else {
            fprintf(stderr, "failed to send mechanism name: %s\n", strerror(errno));
            return -2;
        }
    }
    if ((sent = send(sockfd, " ", 1, 0)) <= 0) {
        if (sent == 0) {
            fprintf(stderr, "server closed connection unexpectedly\n");
            return -2;
        } else {
            fprintf(stderr, "failed to send mechanism name: %s\n", strerror(errno));
            return -2;
        }
    }

    Gsasl_session *session;
    int rc;
    if ((rc = gsasl_client_start(ctx, mechanism, &session)) != GSASL_OK) {
        fprintf(stderr, "failed to initialize client (%s): %s\n", gsasl_strerror_name(rc), gsasl_strerror(rc));
        return -1;
    }

    if ((rc = gsasl_property_set(session, GSASL_AUTHID, "username")) != GSASL_OK) {
        fprintf(stderr, "failed to set property (%s): %s\n", gsasl_strerror_name(rc), gsasl_strerror(rc));
        return -1;
    }
    if ((rc = gsasl_property_set(session, GSASL_PASSWORD, "secret")) != GSASL_OK) {
        fprintf(stderr, "failed to set property (%s): %s\n", gsasl_strerror_name(rc), gsasl_strerror(rc));
        return -1;
    }

    // memmove any remaining data after a newline to the front of buf. The fresh data is everything *after* the
    // newline so we take the window one byte after newline_idx;
    char *fresh_slice = buf + fresh;
    size_t slice_len = bufsz - fresh;
    memmove(buf, fresh_slice, slice_len);
    // The size of the buffer is now only the data we received.
    bufsz = slice_len;

    int8_t retval = authenticate(buf, sizeof(buf), bufsz, session, sockfd);

    gsasl_finish(session);

    return retval;
}

void *get_in_addr(struct sockaddr *sa) {
    if (sa->sa_family == AF_INET) {
        return &(((struct sockaddr_in *) sa)->sin_addr);
    } else if (sa->sa_family == AF_INET6) {
        return &(((struct sockaddr_in6 *) sa)->sin6_addr);
    } else {
        fprintf(stderr, "unknown sa_family %d\n", sa->sa_family);
        exit(-6);
    }
}

int main(int argc, char *argv[]) {
    int8_t retval = 0;
    int rc;
    struct addrinfo hints, *servinfo, *cursor;

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if ((rc = getaddrinfo("localhost", "62185", &hints, &servinfo)) != 0) {
        fprintf(stderr, "failed to resolve server addr: %s\n", gai_strerror(rc));
        retval = -2;
        goto gai_cleanup;
    }

    int sockfd;
    char peer_name[INET6_ADDRSTRLEN];
    for (cursor = servinfo; cursor != NULL; cursor = cursor->ai_next) {
        if ((sockfd = socket(cursor->ai_family, cursor->ai_socktype, cursor->ai_protocol)) < 0) {
            fprintf(stderr, "failed to open socket: %s\n", strerror(errno));
            continue;
        }
        if (connect(sockfd, cursor->ai_addr, cursor->ai_addrlen) == -1) {
            inet_ntop(cursor->ai_family, get_in_addr((struct sockaddr *) cursor->ai_addr), peer_name, sizeof peer_name);
            fprintf(stderr, "failed to connect to %s: %s\n", peer_name, strerror(errno));
            close(sockfd);
            continue;
        }
        break;
    }
    if (cursor == NULL) {
        retval = -2;
        goto gai_cleanup;
    }

    Gsasl *ctx = NULL;
    if ((rc = gsasl_init(&ctx)) != GSASL_OK) {
        fprintf(stderr, "failed to initialize gsasl context (%s): %s\n", gsasl_strerror_name(rc), gsasl_strerror(rc));
        retval = -1;
        goto sockfd_cleanup;
    }

    retval = client(ctx, "SCRAM-SHA-256", sockfd);

    gsasl_done(ctx);

    sockfd_cleanup:
    close(sockfd);

    gai_cleanup:
    freeaddrinfo(servinfo);

    return retval;
}