//
//  launcher.m
//  launcher
//
//  Created by Ethan Arbuckle on 4/10/21.
//

#import "launcher.h"
#include <dlfcn.h>


__attribute__((constructor)) void init(void) {

    NSLog(@"loader injected");
    void (*sym_dlopen)(const char *, int) = dlsym(RTLD_DEFAULT, "dlopen");
    NSLog(@"%p", sym_dlopen);
    sym_dlopen("/Users/ethanarbuckle/Library/Developer/Xcode/DerivedData/hopper_helper-fdadstetzzkavhfyejbkvejwzazs/Build/Products/Debug/libhopper_helper.dylib", 0);
}
