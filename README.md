# netcc
A (C) compiler server, written in C, using libevent for HTTP I/O.
Results are stored into (vault) a TC-style hash-table database.

# Endpoints
POST /              Server accepts C source code in this endpoint. The maximum code length is 4096 bytes. (hardcoded, for now). Responds with an error message, or with a link to the results.
GET /               The form (HTML interface) for submitting source code. Contains javascript code to redirect browser to the results.
GET /XXXXXX         The template for showing results for a given 6-letter key. Contaisn javascript code to fetch results.
GET /api/XXXXXX     Returns the actual results.

# Result format
[status] NEWLINE [source length] NEWLINE [compiler output length] NEWLINE [stdout length] NEWLINE
[source][compiler output][stdout]

A makefile is provided for building the program, dependencies are libevent and libseccomp.

# Running the server
The binary is located in bin, and it will run listening on localhost:3000 (hardcoded, for now).
