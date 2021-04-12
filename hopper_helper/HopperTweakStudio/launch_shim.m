//
//  launch_shim.m
//  launch_shim
//
//  Created by Ethan Arbuckle on 4/10/21.
//

#include <Foundation/Foundation.h>
#include <dlfcn.h>

// Hopper will refuse to load plugins that have unexpected load commands or utilize common posix symbols.
// To work around this, this minimal binary is loaded by Hopper, and from here the real plugin is opened.

__attribute__((constructor)) void init(void) {

    NSLog(@"TweakStudio loader injected");
    
    // Hopper does not allow plugins to use dlopen(), but it does not restrict dlsym().
    // Use dlsym to get the dlopen pointer, then load the real plugin dylib
    void *(*sym_dlopen)(const char *, int) = dlsym(RTLD_DEFAULT, "dlopen");
    const char *dylib = [[@"~/Library/Application Support/Hopper/PlugIns/v4/CPUs/HopperTweakStudio.hopperCPU/HopperTweakStudio" stringByExpandingTildeInPath] UTF8String];
    sym_dlopen(dylib, RTLD_NOW);
}
