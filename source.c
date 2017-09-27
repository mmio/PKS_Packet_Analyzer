#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>

#include "dominik_packettypes.h"

frame_raw* load_frame_raw(char *filename)
{
        FILE *fl = fopen(filename, "r");

        frame_raw *frm = malloc(sizeof *frm);
        
        uint8_t byte;
        size_t iter = 0;
        while (fscanf(fl, "%"SCNx8 , &byte) != EOF)
                frm->bytes[iter++] = byte;

        fclose(fl);
        return frm;
}

int main()
{
        frame_raw *rf = load_frame_raw("p1.txt");
        frame_ethII *e2f = (frame_ethII*)rf;

        for (size_t i = 0; i < 6; ++i)
                printf("%02"PRIx8" ", e2f->dst[i]);
        putchar('\n');
        
        return 0;
}
