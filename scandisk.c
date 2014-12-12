#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>
#include <ctype.h>

#include "bootsect.h"
#include "bpb.h"
#include "direntry.h"
#include "fat.h"
#include "dos.h"

typedef struct node {
    uint16_t cluster;
    struct node *next;
} Node;

void list_clear(Node *list);
void list_append(uint16_t cluster, Node **head);
int find_match(uint16_t cluster, Node *head);


uint16_t get_dirent(struct direntry *dirent, char *buffer)
{
    uint16_t followclust = 0;
    memset(buffer, 0, MAXFILENAME);

    int i;
    char name[9];
    char extension[4];
    uint16_t file_cluster;
    name[8] = ' ';
    extension[3] = ' ';
    memcpy(name, &(dirent->deName[0]), 8);
    memcpy(extension, dirent->deExtension, 3);
    if (name[0] == SLOT_EMPTY)
    {
    return followclust;
    }

    /* skip over deleted entries */
    if (((uint8_t)name[0]) == SLOT_DELETED)
    {
    return followclust;
    }

    if (((uint8_t)name[0]) == 0x2E)
    {
    // dot entry ("." or "..")
    // skip it
        return followclust;
    }

    /* names are space padded - remove the spaces */
    for (i = 8; i > 0; i--) 
    {
    if (name[i] == ' ') 
        name[i] = '\0';
    else 
        break;
    }

    /* remove the spaces from extensions */
    for (i = 3; i > 0; i--) 
    {
    if (extension[i] == ' ') 
        extension[i] = '\0';
    else 
        break;
    }

    if ((dirent->deAttributes & ATTR_WIN95LFN) == ATTR_WIN95LFN)
    {
    // ignore any long file name extension entries
    //
    // printf("Win95 long-filename entry seq 0x%0x\n", dirent->deName[0]);
    }
    else if ((dirent->deAttributes & ATTR_DIRECTORY) != 0) 
    {
        // don't deal with hidden directories; MacOS makes these
        // for trash directories and such; just ignore them.
    if ((dirent->deAttributes & ATTR_HIDDEN) != ATTR_HIDDEN)
        {
            strcpy(buffer, name);
            file_cluster = getushort(dirent->deStartCluster);
            followclust = file_cluster;
        }
    }
    else 
    {
        /*
         * a "regular" file entry
         * print attributes, size, starting cluster, etc.
         */
        strcpy(buffer, name);
        if (strlen(extension))  
        {
            strcat(buffer, ".");
            strcat(buffer, extension);
        }
    }

    return followclust;
}

void write_dirent(struct direntry *dirent, char *filename, 
          uint16_t start_cluster, uint32_t size)
{
    char *p, *p2;
    char *uppername;
    int len, i;

    /* clean out anything old that used to be here */
    memset(dirent, 0, sizeof(struct direntry));

    /* extract just the filename part */
    uppername = strdup(filename);
    p2 = uppername;
    for (i = 0; i < strlen(filename); i++) 
    {
    if (p2[i] == '/' || p2[i] == '\\') 
    {
        uppername = p2+i+1;
    }
    }

    /* convert filename to upper case */
    for (i = 0; i < strlen(uppername); i++) 
    {
    uppername[i] = toupper(uppername[i]);
    }

    /* set the file name and extension */
    memset(dirent->deName, ' ', 8);
    p = strchr(uppername, '.');
    memcpy(dirent->deExtension, "___", 3);
    if (p == NULL) 
    {
    fprintf(stderr, "No filename extension given - defaulting to .___\n");
    }
    else 
    {
    *p = '\0';
    p++;
    len = strlen(p);
    if (len > 3) len = 3;
    memcpy(dirent->deExtension, p, len);
    }

    if (strlen(uppername)>8) 
    {
    uppername[8]='\0';
    }
    memcpy(dirent->deName, uppername, strlen(uppername));
    free(p2);

    /* set the attributes and file size */
    dirent->deAttributes = ATTR_NORMAL;
    putushort(dirent->deStartCluster, start_cluster);
    putulong(dirent->deFileSize, size);

    /* could also set time and date here if we really
       cared... */
}


/* create_dirent finds a free slot in the directory, and write the
   directory entry */

void create_dirent(struct direntry *dirent, char *filename, 
           uint16_t start_cluster, uint32_t size,
           uint8_t *image_buf, struct bpb33* bpb)
{
    while (1) 
    {
    if (dirent->deName[0] == SLOT_EMPTY) 
    {
        /* we found an empty slot at the end of the directory */
        write_dirent(dirent, filename, start_cluster, size);
        dirent++;

        /* make sure the next dirent is set to be empty, just in
           case it wasn't before */
        memset((uint8_t*)dirent, 0, sizeof(struct direntry));
        dirent->deName[0] = SLOT_EMPTY;
        return;
    }

    if (dirent->deName[0] == SLOT_DELETED) 
    {
        /* we found a deleted entry - we can just overwrite it */
        write_dirent(dirent, filename, start_cluster, size);
        return;
    }
    dirent++;
    }
}

void fix_chain(struct direntry *dirent, uint8_t *image_buf, struct bpb33 *bpb, int actual_size) {
    
    uint16_t cluster = getushort(dirent->deStartCluster);
    uint16_t cluster_size = bpb->bpbBytesPerSec * bpb->bpbSecPerClust;

    uint16_t byte_count = 0;
    uint16_t prev_cluster = cluster;

    while (byte_count < actual_size) {
        byte_count += cluster_size;
        prev_cluster = cluster;
        cluster = get_fat_entry(cluster, image_buf, bpb);
    }

    set_fat_entry(prev_cluster, FAT12_MASK & CLUST_EOFS, image_buf, bpb);

    // marking the other clusters pointed to by the FAT chain as free
    while (is_valid_cluster(cluster, bpb)) {
        
        uint16_t oldcluster = cluster;
        cluster = get_fat_entry(cluster, image_buf, bpb);

        set_fat_entry(oldcluster, FAT12_MASK & CLUST_FREE, image_buf, bpb);
    }
}

int count_size_in_clusters(struct direntry *dirent, uint8_t *image_buf, struct bpb33 *bpb, Node **cluster_list)
{
    uint16_t cluster = getushort(dirent->deStartCluster);
    uint16_t cluster_size = bpb->bpbBytesPerSec * bpb->bpbSecPerClust;

    int byte_count = 0;
    list_append(cluster, cluster_list);
    
    if (cluster == (FAT12_MASK & CLUST_BAD)) {
        printf("Bad cluster: cluster number %d \n", cluster);
    }
    
    while (is_valid_cluster(cluster, bpb) && cluster != (FAT12_MASK & CLUST_FREE)) {   
        
        if (cluster == (FAT12_MASK & CLUST_BAD)) {
            //printf("Bad cluster: cluster number %d \n", cluster);
        }

        byte_count += cluster_size;

        cluster = get_fat_entry(cluster, image_buf, bpb);
        list_append(cluster, cluster_list);
    }

    return byte_count;
}


uint32_t calculate_size(uint16_t cluster, uint8_t *image_buf, struct bpb33 *bpb, Node **cluster_list)
{
    uint16_t cluster_size = bpb->bpbBytesPerSec * bpb->bpbSecPerClust;

    uint32_t byte_count = 0;
    list_append(cluster, cluster_list);
    
    if (cluster == (FAT12_MASK & CLUST_BAD)) {
        printf("Bad cluster: cluster number %d \n", cluster);
    }
    
    while (is_valid_cluster(cluster, bpb) && cluster != (FAT12_MASK & CLUST_FREE)) {   
        
        if (cluster == (FAT12_MASK & CLUST_BAD)) {
            //printf("Bad cluster: cluster number %d \n", cluster);
        }

        byte_count += cluster_size;

        cluster = get_fat_entry(cluster, image_buf, bpb);
        list_append(cluster, cluster_list);
    }

    return byte_count;
}

int check_and_fix(struct direntry* dirent, char* filename, uint8_t *image_buf, struct bpb33* bpb, Node **cluster_list) {

    int problem_found = 0;
    int size_in_clusters = count_size_in_clusters(dirent, image_buf, bpb, cluster_list);
    uint32_t size_in_dirent = getulong(dirent->deFileSize);

    if (size_in_dirent != 0 && size_in_dirent < size_in_clusters - 512 ) { // believe the dir entry; fix the FAT
        printf("Inconsistent file: %s (size in dir entry: %d, size in FAT chain: %d) \n", filename, size_in_dirent, size_in_clusters);
        fix_chain(dirent, image_buf, bpb, size_in_dirent);
        problem_found = 1;
    }

    else if (size_in_dirent != 0 && size_in_dirent > size_in_clusters) { // believe the FAT chain, fix the dir entry
        printf("Inconsistent file: %s (size in dir entry: %d, size in FAT chain: %d) \n", filename, size_in_dirent, size_in_clusters);
        putulong(dirent->deFileSize, size_in_clusters);
        problem_found = 1;
    }

    return problem_found;
}

int follow_dir(uint16_t cluster, int indent,
        uint8_t *image_buf, struct bpb33* bpb, Node** cluster_list)
{   
    int problem_found = 0;
    while (is_valid_cluster(cluster, bpb))
    {   
        list_append(cluster, cluster_list);
        struct direntry *dirent = (struct direntry*)cluster_to_addr(cluster, image_buf, bpb);

        int numDirEntries = (bpb->bpbBytesPerSec * bpb->bpbSecPerClust) / sizeof(struct direntry);
        char buffer[MAXFILENAME];

        int i = 0;
        for ( ; i < numDirEntries; i++) {
                
                list_append(cluster, cluster_list);

                uint16_t followclust = get_dirent(dirent, buffer);
        
                if (check_and_fix(dirent, buffer, image_buf, bpb, cluster_list)) {
                    problem_found = 1;
                }

                if (followclust) {
                    if (follow_dir(followclust, indent+1, image_buf, bpb, cluster_list)) {
                        problem_found = 1;
                    }
                }
                
                dirent++;
        }

        cluster = get_fat_entry(cluster, image_buf, bpb);
    }
    return problem_found;
}


void traverse_root(uint8_t *image_buf, struct bpb33* bpb)
{
    Node* list = NULL;
    int problem_found = 0;
    uint16_t cluster = 0;

    struct direntry *dirent = (struct direntry*)cluster_to_addr(cluster, image_buf, bpb);

    char buffer[MAXFILENAME];

    int i = 0;
    for ( ; i < bpb->bpbRootDirEnts; i++)
    {
        uint16_t followclust = get_dirent(dirent, buffer);

        if (check_and_fix(dirent, buffer, image_buf, bpb, &list)) {
            problem_found = 1;
        }
        list_append(followclust, &list);
        if (is_valid_cluster(followclust, bpb)) {
            list_append(followclust, &list);
            if (follow_dir(followclust, 1, image_buf, bpb, &list)) {
                problem_found = 1;
            }
        }

        dirent++;
    }
    
    int orphan_found = 0;
    
    uint16_t check_clust = (FAT12_MASK & CLUST_FIRST);
    
    for ( ; check_clust < 2880; check_clust++) {
        if (!find_match(check_clust, list) && (get_fat_entry(check_clust, image_buf, bpb) != CLUST_FREE))  {
            printf("Orphan cluster found; cluster number %d \n", check_clust);
            problem_found = 1;
            orphan_found = 1;
        }
    } 
    
    int orphan_count = 0;
    
    uint16_t clust = (FAT12_MASK & CLUST_FIRST);
    
    while (orphan_found) {
        //orphan_count++; 
        orphan_found = 0;
        for ( ; clust  < 2880; clust++) {
            if (!find_match(clust, list) && (get_fat_entry(clust, image_buf, bpb) != CLUST_FREE))  {
                problem_found = 1;
                orphan_found = 1;
                break;
            }
        } 
        if (orphan_found) {
            orphan_count++;
            cluster = 0;
            dirent = (struct direntry*)cluster_to_addr(cluster, image_buf, bpb);
            char filename[13];
            memset(filename, '\0', 13);
            strcat(filename, "found");
            char str[3];
            memset(str, '\0', 3);
            int orphan_count_copy = orphan_count;
            sprintf(str, "%d", orphan_count_copy);
            strcat(filename, str);
            strcat(filename, ".dat");
            int size_in_clusters = calculate_size(clust, image_buf, bpb, &list);
            list_append(clust, &list);
            create_dirent(dirent, filename, clust, size_in_clusters, image_buf, bpb);
            problem_found = 1;
        }
         
    }
    
    if (problem_found) {
         // do it all again to ensure it's consistent...
        printf("All issues were fixed, system is now consistent. \n");
    }
    else {
        printf("No problems were found, the system is consistent. \n");
    }
    list_clear(list);
}

void list_clear(Node *list) {
    while (list != NULL) {
        Node *tmp = list;
        list = list->next;
        free(tmp);
    }
}

void list_append(uint16_t cluster, Node **head) {
    Node *newnode = malloc(sizeof(Node));
    newnode->cluster = cluster;
    newnode->next = NULL;
    Node *curr = *head;
    if (curr == NULL) {
        *head = newnode;
        return;
    }
    while (curr->next != NULL) {
        curr = curr->next;
    }
    curr->next = newnode;
    newnode->next = NULL;
}

int find_match(uint16_t cluster, Node *head) {
    int match_found = 0;
    Node *curr = head;
    while (curr != NULL) {
        if (cluster == curr->cluster) {
            match_found = 1;
            break;
        }
        curr = curr->next;
    }
    return match_found;
}

void usage(char *progname) {
    fprintf(stderr, "usage: %s <imagename>\n", progname);
    exit(1);
}


int main(int argc, char** argv) {
    uint8_t *image_buf;
    int fd;
    struct bpb33* bpb;
    if (argc < 2) {
	   usage(argv[0]);
    }

    image_buf = mmap_file(argv[1], &fd);
    bpb = check_bootsector(image_buf);

    traverse_root(image_buf, bpb);

    unmmap_file(image_buf, &fd);
    return 0;
}
