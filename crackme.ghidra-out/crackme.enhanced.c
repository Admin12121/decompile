#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void enforce_expected_binary_name(const char *program_path) {
    const char *base_name = program_path;
    const char *cursor = program_path;

    while (*cursor != '\0') {
        if (*cursor == '/') {
            base_name = cursor + 1;
        }
        cursor++;
    }

    if (strcmp(base_name, "crackme") != 0) {
        puts("Nothing interesting here. Move along.");
        exit(0);
    }
}

static void check_magic_number(int magic_number) {
    if (magic_number == 0x6042) {
        printf("FLAG: %s\n", "softwarica_ctf{r3v3aled_1n_th3_depths_of_r3v3rs3_3ngin33r1ng}");
    } else {
        puts("softwarica_ctf{fake_flag_try_harder_lol}");
    }
}

int main(int argc, char **argv) {
    int magic_number;

    (void)argc;
    enforce_expected_binary_name(argv[0]);
    printf("Enter the magic number: ");
    scanf("%d", &magic_number);
    check_magic_number(magic_number);

    return 0;
}
