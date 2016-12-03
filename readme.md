Triple Data Encryption Algorithm

Header only and easy to use

Demo code:

```cpp
#include <iostream>
#include "des2/des.h"

int main(int, char**)
{
    //3des
    DES3_Cipher d3("00000000abcdefgheeeeeeee");  //00000000abcdefgh
    auto ff = d3.encrypt("goo12345");
    auto ok_ff = d3.decrypt(ff);

    //DES
    DES_Cipher d1("12345678");  //00000000abcdefgh
    auto ff1 = d3.encrypt("goo12345");
    auto ok_ff1 = d3.decrypt(ff);
}

```
