# lab4 File Recovery
## Overview  
In this lab, you will work on the data stored in the FAT32 file system directly, without the OS file system support. You will implement a tool that recovers a deleted file specified by the user.
For simplicity, you can assume that the deleted file is in the root directory. Therefore, you don’t need to search subdirectories.

## Your tasks
**Important:** before running your ```nyufile``` program, please make sure that your FAT32 disk is **unmounted**.

### Milestone 1: validate usage
There are several ways to invoke your ```nyufile``` program. Here is its usage:
```
$ ./nyufile
Usage: ./nyufile disk <options>
  -i                     Print the file system information.
  -l                     List the root directory.
  -r filename [-s sha1]  Recover a contiguous file.
  -R filename -s sha1    Recover a possibly non-contiguous file.
```
The first argument is the filename of the disk image. After that, the options can be one of the following:

- ```-i```
- ```-l```
- ```-r filename```
- ```-r filename -s sha1```
- ```-R filename -s sha1```  
  
You need to check if the command-line arguments are valid. If not, your program should print the above usage information and exit.

### Milestone 2: print the file system information
If your ```nyufile``` program is invoked with option ```-i```, it should print the following information about the FAT32 file system:

- Number of FATs;
- Number of bytes per sector;
- Number of sectors per cluster;
- Number of reserved sectors.  
  
Your output should be in the following format:
```
$ ./nyufile fat32.disk -i
Number of FATs = 2
Number of bytes per sector = 512
Number of sectors per cluster = 1
Number of reserved sectors = 32
```
For all milestones, you can assume that ```nyufile``` is invoked **while the disk is unmounted**.

### Milestone 3: list the root directory
If your ```nyufile``` program is invoked with option ```-l```, it should list all valid entries in the root directory with the following information:

- **Filename.** Similar to ```/bin/ls -p```, if the entry is a directory, you should **append a ```/``` indicator**.
- **File size.**
- **Starting cluster.**  
  
You should also print the total number of entries at the end. Your output should be in the following format:
```
$ ./nyufile fat32.disk -l
HELLO.TXT (size = 14, starting cluster = 3)
DIR/ (size = 0, starting cluster = 4)
EMPTY (size = 0, starting cluster = 0)
Total number of entries = 3
```
Here are a few assumptions:  

- You **should not** list entries marked as deleted.
- You don’t need to print the details inside subdirectories.
- For all milestones, there will be no long filename (LFN) entries. (If you have accidentally created LFN entries when you test your program, don’t worry. You can just skip the LFN entries and print only the 8.3 filename entries.)
- All files and directories, including the root directory, may span across **more than one cluster**.
- There may be **empty** files.
### Milestone 4: recover a small file
If your ```nyufile``` program is invoked with option ```-r filename```, it should recover the deleted file with the specified name. The workflow is better illustrated through an example:
```
$ sudo mount -o umask=0 fat32.disk /mnt/disk
$ ls -p /mnt/disk
DIR/  EMPTY  HELLO.TXT
$ cat /mnt/disk/HELLO.TXT
Hello, world.
$ rm /mnt/disk/HELLO.TXT
$ ls -p /mnt/disk
DIR/  EMPTY
$ sudo umount /mnt/disk
$ ./nyufile fat32.disk -l
DIR/ (size = 0, starting cluster = 4)
EMPTY (size = 0, starting cluster = 0)
Total number of entries = 2
$ ./nyufile fat32.disk -r HELLO
HELLO: file not found
$ ./nyufile fat32.disk -r HELLO.TXT
HELLO.TXT: successfully recovered
$ ./nyufile fat32.disk -l
HELLO.TXT (size = 14, starting cluster = 3)
DIR/ (size = 0, starting cluster = 4)
EMPTY (size = 0, starting cluster = 0)
Total number of entries = 3
$ sudo mount -o umask=0 fat32.disk /mnt/disk
$ ls -p /mnt/disk
DIR/  EMPTY  HELLO.TXT
$ cat /mnt/disk/HELLO.TXT
Hello, world.
```
For all milestones, you only need to recover **regular files** (including empty files, but not directory files) in the **root directory**. When the file is successfully recovered, your program should print filename: ```successfully recovered```.
  
For all milestones, you can assume that no other files or directories are created or modified since the deletion of the target file. However, multiple files may be deleted.
  
Besides, for all milestones, you don’t need to update the FSINFO structure because most operating systems don’t care about it.
  
Here are a few assumptions specifically for Milestone 4:
  
- The size of the deleted file is no more than the size of a cluster.
- At most one deleted directory entry matches the given filename. If no such entry exists, your program should print filename: ```file not found```.
  
### Milestone 5: recover a large contiguously-allocated file
Now, you will recover a file that is larger than one cluster. Nevertheless, for Milestone 5, you can assume that such a file is allocated contiguously. You can continue to assume that at most one deleted directory entry matches the given filename. If no such entry exists, your program should print filename: ```file not found```.

### Milestone 6: detect ambiguous file recovery requests
In Milestones 4 and 5, you assumed that at most one deleted directory entry matches the given filename. However, multiple files whose names differ only in the first character would end up having the same name when deleted. Therefore, you may encounter more than one deleted directory entry matching the given filename. When that happens, your program should print ```filename: multiple candidates found and abort```.

This scenario is illustrated in the following example:
```
$ sudo mount -o umask=0 fat32.disk /mnt/disk
$ echo "My last name is Tang." > /mnt/disk/TANG.TXT
$ echo "My first name is Yang." > /mnt/disk/YANG.TXT
$ sync
$ rm /mnt/disk/TANG.TXT /mnt/disk/YANG.TXT
$ sudo umount /mnt/disk
$ ./nyufile fat32.disk -r TANG.TXT
TANG.TXT: multiple candidates found
```

### Milestone 7: recover a contiguously-allocated file with SHA-1 hash
To solve the aforementioned ambiguity, the user can provide a SHA-1 hash via command-line option ```-s sha1``` to help identify which deleted directory entry should be the target file.

In short, a SHA-1 hash is a 160-bit fingerprint of a file, often represented as 40 hexadecimal digits. For the purpose of this lab, you can assume that identical files always have the same SHA-1 hash, and different files always have vastly different SHA-1 hashes. Therefore, even if multiple candidates are found during recovery, at most one will match the given SHA-1 hash.

This scenario is illustrated in the following example:
```
$ ./nyufile fat32.disk -r TANG.TXT -s c91761a2cc1562d36585614c8c680ecf5712e875
TANG.TXT: successfully recovered with SHA-1
$ ./nyufile fat32.disk -l
HELLO.TXT (size = 14, starting cluster = 3)
DIR/ (size = 0, starting cluster = 4)
EMPTY (size = 0, starting cluster = 0)
TANG.TXT (size = 22, starting cluster = 5)
Total number of entries = 4
```
When the file is successfully recovered with SHA-1, your program should print ```filename: successfully recovered with SHA-1```.

Note that you can use the ```sha1sum``` command to compute the SHA-1 hash of a file:
```
$ sha1sum /mnt/disk/TANG.TXT
c91761a2cc1562d36585614c8c680ecf5712e875  /mnt/disk/TANG.TXT
```
Also note that it is possible that the file is empty or occupies only one cluster. The SHA-1 hash for an empty file is ```da39a3ee5e6b4b0d3255bfef95601890afd80709```.

If no such file matches the given SHA-1 hash, your program should print ```filename: file not found```. For example:
```
$ ./nyufile fat32.disk -r TANG.TXT -s 0123456789abcdef0123456789abcdef01234567
TANG.TXT: file not found
```
The OpenSSL library provides a function ```SHA1()```, which computes the SHA-1 hash of ```d[0...n-1]``` and stores the result in ```md[0...SHA_DIGEST_LENGTH-1]```:
```C
#include <openssl/sha.h>

#define SHA_DIGEST_LENGTH 20

unsigned char *SHA1(const unsigned char *d, size_t n, unsigned char *md);
```
You need to add the compiler option ```-l crypto``` to link with the OpenSSL library.

### Milestone 8: recover a non-contiguously allocated file
Finally, the clusters of a file are no longer assumed to be contiguous. You have to try every permutation of unallocated clusters on the file system in order to find the one that matches the SHA-1 hash.

The command-line option is ```-R filename -s sha1```. The SHA-1 hash must be given.

Note that it is possible that the file is empty or occupies only one cluster. If so, ```-R``` behaves the same as ```-r```, as described in Milestone 7.

For Milestone 8, you can assume that the entire file is within the first 12 clusters, so that a brute-force search is feasible.

If you cannot find a file that matches the given SHA-1 hash, your program should print ```filename: file not found.```

