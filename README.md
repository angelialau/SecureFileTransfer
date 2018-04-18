# SecureFileTransfer
50.005 CSE Programming Assignment 2

### Authors
Angelia Lau Kah Mun 1002417
Tham Yee Ting 1002516

### Instructions on how to run the programs:
1. Rename `filename` variable in ClientCP1 and ClientCP2 to the name of the test file you want to run. For example, to run the test file `rr0.txt`, the corresponding line should be:
```String filename = "rr0.txt";```

2. Change `hostName` variable in ClientCP1 and ClientCP2 to the local IP address of the server machine. For example, to run on localhost with the IP address 127.0.0.1, the corresponding line should be:
```String hostName = "127.0.0.1";```

3. Run ServerCP1 (within your IDE or terminal) until you see the line `"Waiting for clients"`.
4. Then, run ClientCP1 and wait for completion, denoted by `"Closing connection..."`.
5. The file that has been uploaded to the server will be saved under the directory `/recv` with the same name as the file specified under step 1. If encryption and decryption of the files have been done properly, the contents of these two files should be the same. 
6. Repeat steps 3 to 5 for ServerCP2 and ClientCP2. You will notice that CP2 takes a much shorter time than CP1.

### Source code
The files can be located within the `/src` directory. 

### Test files
Our test files range from `rr0.txt` to `rr7.txt`, each twice as large as the preceeding one. `rr0.txt` begins from 1250 lines of text, while `rr7.txt` ends with 16000 lines. 
