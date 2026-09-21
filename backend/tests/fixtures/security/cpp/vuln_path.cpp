#include <fstream>
#include <cstdio>
#include <string>

void read_user_file(int argc, char **argv) {
    std::string path = argv[1];
    fopen(path.c_str(), "r");
}
