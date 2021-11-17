#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#define handle_error(msg) do { perror(msg); exit(EXIT_FAILURE); } while (0)

#pragma pack(push,1)
typedef struct DirEntry {
  unsigned char  DIR_Name[11];      // File name
  unsigned char  DIR_Attr;          // File attributes
  unsigned char  DIR_NTRes;         // Reserved
  unsigned char  DIR_CrtTimeTenth;  // Created time (tenths of second)
  unsigned short DIR_CrtTime;       // Created time (hours, minutes, seconds)
  unsigned short DIR_CrtDate;       // Created day
  unsigned short DIR_LstAccDate;    // Accessed day
  unsigned short DIR_FstClusHI;     // High 2 bytes of the first cluster address
  unsigned short DIR_WrtTime;       // Written time (hours, minutes, seconds
  unsigned short DIR_WrtDate;       // Written day
  unsigned short DIR_FstClusLO;     // Low 2 bytes of the first cluster address
  unsigned int   DIR_FileSize;      // File size in bytes. (0 for directories)
} DirEntry;
#pragma pack(pop)

#pragma pack(push,1)
typedef struct BootEntry {
  unsigned char  BS_jmpBoot[3];     // Assembly instruction to jump to boot code
  unsigned char  BS_OEMName[8];     // OEM Name in ASCII
  unsigned short BPB_BytsPerSec;    // Bytes per sector. Allowed values include 512, 1024, 2048, and 4096
  unsigned char  BPB_SecPerClus;    // Sectors per cluster (data unit). Allowed values are powers of 2, but the cluster size must be 32KB or smaller
  unsigned short BPB_RsvdSecCnt;    // Size in sectors of the reserved area
  unsigned char  BPB_NumFATs;       // Number of FATs
  unsigned short BPB_RootEntCnt;    // Maximum number of files in the root directory for FAT12 and FAT16. This is 0 for FAT32
  unsigned short BPB_TotSec16;      // 16-bit value of number of sectors in file system
  unsigned char  BPB_Media;         // Media type
  unsigned short BPB_FATSz16;       // 16-bit size in sectors of each FAT for FAT12 and FAT16. For FAT32, this field is 0
  unsigned short BPB_SecPerTrk;     // Sectors per track of storage device
  unsigned short BPB_NumHeads;      // Number of heads in storage device
  unsigned int   BPB_HiddSec;       // Number of sectors before the start of partition
  unsigned int   BPB_TotSec32;      // 32-bit value of number of sectors in file system. Either this value or the 16-bit value above must be 0
  unsigned int   BPB_FATSz32;       // 32-bit size in sectors of one FAT
  unsigned short BPB_ExtFlags;      // A flag for FAT
  unsigned short BPB_FSVer;         // The major and minor version number
  unsigned int   BPB_RootClus;      // Cluster where the root directory can be found
  unsigned short BPB_FSInfo;        // Sector where FSINFO structure can be found
  unsigned short BPB_BkBootSec;     // Sector where backup copy of boot sector is located
  unsigned char  BPB_Reserved[12];  // Reserved
  unsigned char  BS_DrvNum;         // BIOS INT13h drive number
  unsigned char  BS_Reserved1;      // Not used
  unsigned char  BS_BootSig;        // Extended boot signature to identify if the next three values are valid
  unsigned int   BS_VolID;          // Volume serial number
  unsigned char  BS_VolLab[11];     // Volume label in ASCII. User defines when creating the file system
  unsigned char  BS_FilSysType[8];  // File system type label in ASCII
} BootEntry;
#pragma pack(pop)

void process_name(char* raw, char* new){
    char* p = new;
    *p = 0;
    if(raw[0]==0) return;
    if(raw[0]==0xe5)return;
    for(int i=0;i<8;i++){
        if(raw[i]==0x20)break;
        else *p++ = raw[i];
    }
    if(new[0]==0) return;
    *p = 0x2e;
    for(int i=8;i<11;i++){
        if(raw[i]==0x20)break;
        else *++p = raw[i];
    }
    if((*p)==0x2e) *p=0;
    *++p=0;
    return;
}


int main(int argc, char **argv){
    extern char *optarg;
    extern int optind, opterr, optopt;
    int opt;
    char* error_message = "Usage: ./nyufile disk <options>\n  -i                     Print the file system information.\n  -l                     List the root directory.\n  -r filename [-s sha1]  Recover a contiguous file.\n  -R filename -s sha1    Recover a possibly non-contiguous file.\n";
    int i=0, l=0, r=0, rr=0, s=0;
    char *file_name;
    while((opt = getopt(argc, argv, "ilr:R:s:")) != -1){
        switch(opt){
        case 'i':
            i=1;
            break;
        case 'l':
            l=1;
            break;
        default:
            fprintf(stderr, error_message);
            exit(EXIT_FAILURE);     
        }
    }
    if (optind >= argc) {
        fprintf(stderr, error_message);
        exit(EXIT_FAILURE);
    }
    file_name = argv[optind];
    
    int fd;
    struct stat sb;
    char *addr;
    off_t offset, pa_offset;
    size_t length_file;
    fd = open(file_name, O_RDONLY);
    if (fd == -1)
        handle_error("open");
    if (fstat(fd, &sb) == -1) // To obtain file size 
        handle_error("fstat"); 
    pa_offset = 0 & ~(sysconf(_SC_PAGE_SIZE) - 1);
    length_file = sb.st_size;
    addr = mmap(NULL, length_file - pa_offset, PROT_READ, MAP_PRIVATE, fd, pa_offset);
    if (addr == MAP_FAILED)
            handle_error("mmap");
    BootEntry *disk = (BootEntry*)malloc(sizeof(BootEntry));
    memcpy(disk, addr, sizeof(BootEntry));
    int NumFATs = disk->BPB_NumFATs;
    int BytsPerSec = disk->BPB_BytsPerSec;
    int SecPerClus = disk->BPB_SecPerClus;
    int RsvdSecCnt = disk->BPB_RsvdSecCnt;
    int FATSz32 = disk->BPB_FATSz32;
    int RootClus = disk->BPB_RootClus;
    int fat_start = BytsPerSec*RsvdSecCnt;
    int cluster_start = BytsPerSec*(RsvdSecCnt + NumFATs*FATSz32);
    if(i==1){
        printf("Number of FATs = %d\n", NumFATs);
        printf("Number of bytes per sector = %d\n", BytsPerSec);
        printf("Number of sectors per cluster = %d\n", SecPerClus);
        printf("Number of reserved sectors = %d\n", RsvdSecCnt);
        return 0;
    }
    if(l==1){
        int total_entry = 0;
        DirEntry *entry = (DirEntry*)malloc(sizeof(DirEntry));
        int offset_a;
        char* file_name = (char*)malloc(13*sizeof(char));
        int temp_root_dir;
        int root_fat = (RootClus - 2) * SecPerClus + 2;
        int starting_cluster;
        do{
            temp_root_dir = cluster_start + (root_fat-2)*BytsPerSec;
            for(offset_a=0;offset_a<BytsPerSec;offset_a+=sizeof(DirEntry)){
                memcpy(entry, addr+temp_root_dir+offset_a, sizeof(DirEntry));
                process_name(entry->DIR_Name, file_name);
                if(file_name[0]==0)continue;
                else{
                    total_entry++;
                    if((entry->DIR_Attr & 0x10) == 0)
                        printf("%s (size= ", file_name);
                    else printf("%s/ (size= ", file_name);
                    printf("%d, ", entry->DIR_FileSize);
                    starting_cluster = entry->DIR_FstClusLO;
                    starting_cluster += entry->DIR_FstClusHI*0x10000;
                    printf("starting cluster = %d)\n", starting_cluster);
                }
            }

            memcpy(&root_fat, addr + fat_start + root_fat * 4, 4);
        }while(root_fat < 0x0ffffff8);
        printf("Total number of entries = %d\n", total_entry);
        return 0;
    }


}