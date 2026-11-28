#include <stdio.h>

int multiply(int i){
    return i * i;
}

int main(){
    int i = 2;
    int factor;
    scanf("%d", &factor);
    
    while (i <= factor) {
        i = multiply(i);
    }
}

