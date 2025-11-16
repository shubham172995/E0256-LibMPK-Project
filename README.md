# E0256-LibMPK-Project

1. Go to the directory - E0256-libmpkProject
2. Make the project - Run "$ make"
3. Now, you get two files. One is a shared library which is 'libtrusted.so' which contains trusted calls. Another is a main executable.
4. Just run '$ ./main'. This runs the application.
    The application has a Crypto Vault. The application uses 12 pages to contain Crypto keys. You can have 16 at max. I am using 15.
    Each page has some multiple number of keys. Everytime a key is created, it is stored in one of these pages.
    There are indices attached to each key. I have a global table which contains metadata of keys.
    It contains address of ith key, and other metadata of the key which is used during encryption or decryption, etc.
    Metadata also contains the pkey of the page it is stored in. Essentially, this is the key used to protect the page which contains this key.
    All the pages are protected by MPK. Each access is preceded by setting relevant permissions to the page by calling 'pkey_set()' function.

TO RUN YOUR OWN BINARY, JUST LOOK AT THE 'main.c' FILE. IT JUST USES 'trusted_crypto.h' AND CALLS ENCRYPTION AND DECRYPTION FUNCTIONS.

Essentially, you would need a structure entity called 'CipherEnvelope'. The 'main.c' also has some code to check if some other key is used to decrypt a cipher, it won't be successful.

This marks the PHASE-1.

For Phase-2, there is a file which uses Dyninst, "find_pkey_set.cpp".
1. This is supposed to find pkey_set in untrusted library and replace that with a benign function 'my_pkey_set' defined in libtrusted.so
2. So, it is essential to link lintrusted.so as well.
3. To run this, we need to do following steps:

    export PREFIX=<Path to Dyninst>

    g++ -std=c++11 find_pkey_set.cpp \
    -I"$PREFIX/include" \
    -I"$PREFIX/include/dyninstAPI" \
    -L"$PREFIX/lib" \
    -Wl,-rpath,$PREFIX/lib \
    -ldyninstAPI -linstructionAPI -lparseAPI -lsymtabAPI \
    -o find_pkey

    ./find_pkey <Executable> <mode of running> <PID if it is a running process> <Path to libtrusted.so>

THIS DID NOT WORK WITH STATIC BINARIES. I WAS UNABLE TO TEST FOR RUNNING BINARIES DUE TO NO SUDO ACCESS TO AMAZON-GPU SERVER.

SO, RESORTED TO ANOTHER METHOD.

After the make is done, do the following:

1. Set an environment variable, 'ALLOW_PKEY_MODULE' which is used to contain libraries that can access the function pkey_set() legitimately as follows:
    '$ export ALLOW_PKEY_MODULE=<Path to libtrusted.so>$
2. Make a shared library of blocker file, 'block_pkey_set.c' as follows:
    '$ gcc -shared -fPIC -O2 -o libblockpkey.so block_pkey_set.c -ldl'
3. Test the applications.
    eg. For an untrusted binary '$ LD_PRELOAD=<Path to libblockpkey.so> <executable>'
    eg. For authorised case where proper use is made, for instance in the main file which comes with the zip when you do make,
    '$  LD_PRELOAD=<Path to libblockpkey.so> <path to main inside the directory of project>'

For example, go to src directory and compile a test file, '$ gcc test_for_pkey_untrusted.c -o test_pkey'
Do '$ export ALLOW_PKEY_MODULE=<Path to libtrusted.so>'
Do '$ gcc -shared -fPIC -O2 -o libblockpkey.so block_pkey_set.c -ldl'
Do '$ export ALLOW_PKEY_MODULE=/data4/home/shubhamshar1/e0256/E0256-LibMPK-Project/libtrusted.so'
Do '$ LD_PRELOAD=./libblockpkey.so ./test_pkey' -> This should fail.
Do '$ LD_PRELOAD=./libblockpkey.so ../main' -> This should pass.