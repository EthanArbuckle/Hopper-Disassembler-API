//
//  hopper_helper.m
//  hopper_helper
//
//  Created by Ethan Arbuckle on 4/6/21.
//

#import <Foundation/Foundation.h>
#import "GCDWebServerDataRequest.h"
#import "GCDWebServer.h"
#include <objc/message.h>
#include <dlfcn.h>
#import "handlers.h"


static NSDictionary *(^allDocuments)(void) = ^id() {
    NSMutableDictionary *docNamesAndDocs = [[NSMutableDictionary alloc] init];
    // allDocuments = +[HopperAppDelegate allDocuments];
    NSArray *allDocuments = ((id (*)(id, SEL))objc_msgSend)(NSClassFromString(@"HopperAppDelegate"), NSSelectorFromString(@"allDocuments"));
    
    for (id document in allDocuments) {
        // documentName = [document documentName]
        NSString *documentName = ((id (*)(id, SEL))objc_msgSend)(document, NSSelectorFromString(@"documentName"));
        docNamesAndDocs[documentName] = document;
    }
    return docNamesAndDocs;
};

__attribute__((constructor)) void init(void) {
    
    NSLog(@"real TweakStudio plugin injected");
    
    // Create server
    GCDWebServer* webServer = [[GCDWebServer alloc] init];
    void (^addPostHandler)(NSString *path, HandlerBlock) = ^void(NSString *path, id (^handler)(NSDictionary *requestData, id hopperDocument, id disassembledFile)) {
        
        [webServer addHandlerForMethod:@"POST" path:path requestClass:[GCDWebServerDataRequest class] processBlock:^GCDWebServerResponse * _Nullable(__kindof GCDWebServerDataRequest * _Nonnull request) {
            
            NSDictionary *requestBody = [NSJSONSerialization JSONObjectWithData:[request data] options:0 error:nil];
            NSString *requestedDocument = requestBody[@"document_name"];

            id hopperDocument = nil;
            id disassembledFile = nil;
            if (requestedDocument) {
                
                // Search for a document with the requested name
                NSDictionary *documents = allDocuments();
                for (NSString *documentName in documents) {
                    if ([documentName isEqualToString:requestedDocument]) {
                        hopperDocument = documents[documentName];
                        break;
                    }
                }
                                
                disassembledFile = ((id (*)(id, SEL))objc_msgSend)(hopperDocument, NSSelectorFromString(@"disassembledFile"));
            }
            
            id handlerResponse = handler(requestBody, hopperDocument, disassembledFile);
            NSMutableDictionary *wrappedResponse = [[NSMutableDictionary alloc] init];
            
            wrappedResponse[@"data"] = handlerResponse;
            if (!handlerResponse) {
                // todo errors
                wrappedResponse[@"error"] = @"nondescript error";
            }
        
            return [GCDWebServerDataResponse responseWithJSONObject:wrappedResponse];
        }];
    };

    addPostHandler(@"/strings", StringsHandler);
    addPostHandler(@"/segments", SegmentsHandler);
    addPostHandler(@"/procedures", ProceduresHandler);
    addPostHandler(@"/decompile", DecompileHandler);
    addPostHandler(@"/disassemble", DisassembleHandler);
    addPostHandler(@"/filepath", FilePathHandler);
    addPostHandler(@"/terminate", TerminateHandler);
    addPostHandler(@"/procedure_signature", ProcedureSignatureHandler);
    addPostHandler(@"/status", StatusHandler);
    addPostHandler(@"/xrefs", XrefsHandler);
    
    [webServer addHandlerForMethod:@"GET" path:@"/documents" requestClass:[GCDWebServerRequest class] processBlock:^GCDWebServerResponse * _Nullable(__kindof GCDWebServerRequest * _Nonnull request) {
        
        NSArray *allDocumentNames = [allDocuments() allKeys];
        return [GCDWebServerDataResponse responseWithJSONObject:@{@"data": allDocumentNames}];
    }];
    
    int serverPort = 52349;
    if (![webServer startWithPort:serverPort bonjourName:nil]) {

        NSLog(@"Hopper already running on port: %d", serverPort);
        exit(0);
    }
}
