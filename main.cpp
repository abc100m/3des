#include <iostream>
#include "des2/des.h"

int main(int, char**)
{
    DES_Trait xyz;

    //DES_Cipher d1("aaaa");
    DES3_Cipher d3("00000000abcdefgheeeeeeee");  //00000000abcdefgh
    auto ff = d3.encrypt("goo12345");
    //d1.encrypt("yes");

    auto ok_ff = d3.decrypt(ff);
    unsigned char * ddd = (unsigned char*)ff.data();
   
    std::cout << "Hello, world!\n" << ff;

}
