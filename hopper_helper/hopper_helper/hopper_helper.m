//
//  hopper_helper.m
//  hopper_helper
//
//  Created by Ethan Arbuckle on 4/6/21.
//

#import "hopper_helper.h"
#import "GCDWebServer.h"
#import "GCDWebServerDataResponse.h"
#import "GCDWebServerDataRequest.h"
#include <dlfcn.h>
#include <objc/message.h>

#define responseError [GCDWebServerDataResponse responseWithText:@"error"]

__attribute__((constructor)) void init(void) {
    
    NSLog(@"helper injected");
    
    // Create server
    GCDWebServer* webServer = [[GCDWebServer alloc] init];
    
    // Add a handler to respond to GET requests on any URL
    [webServer addDefaultHandlerForMethod:@"GET" requestClass:[GCDWebServerRequest class] processBlock:^GCDWebServerResponse *(GCDWebServerRequest* request) {
      
      return [GCDWebServerDataResponse responseWithHTML:@"<html><body><p>Hello World</p></body></html>"];
      
    }];
    
    NSDictionary *(^allDocuments)(void) = ^id() {
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
    
    id (^getDocumentWithName)(NSString *) = ^id(NSString *requestedName) {
        id hopperDocument = nil;
        NSDictionary *documents = allDocuments();
        for (NSString *documentName in documents) {
            if ([documentName isEqualToString:requestedName]) {
                hopperDocument = documents[documentName];
            }
        }
        return hopperDocument;
    };

    [webServer addHandlerForMethod:@"GET" path:@"/documents" requestClass:[GCDWebServerRequest class] processBlock:^GCDWebServerResponse * _Nullable(__kindof GCDWebServerRequest * _Nonnull request) {
        
        NSArray *allDocumentNames = [allDocuments() allKeys];
        return [GCDWebServerDataResponse responseWithJSONObject:allDocumentNames];
    }];
    
    [webServer addHandlerForMethod:@"POST" path:@"/strings" requestClass:[GCDWebServerDataRequest class] processBlock:^GCDWebServerResponse * _Nullable(__kindof GCDWebServerDataRequest * _Nonnull request) {
        
        NSDictionary *requestBody = [NSJSONSerialization JSONObjectWithData:[request data] options:0 error:nil];
        NSString *requestedDocument = requestBody[@"document_name"];
        if (!requestedDocument) {
            return responseError;
        }
        
        id document = getDocumentWithName(requestedDocument);
        if (!document) {
            return responseError;
        }

        id disassembledFile = ((id (*)(id, SEL))objc_msgSend)(document, NSSelectorFromString(@"disassembledFile"));
        NSArray *allStrings = ((id (*)(id, SEL))objc_msgSend)(disassembledFile, NSSelectorFromString(@"allStrings"));
        
        return [GCDWebServerDataResponse responseWithJSONObject:allStrings];
    }];
    
    [webServer addHandlerForMethod:@"POST" path:@"/segments" requestClass:[GCDWebServerDataRequest class] processBlock:^GCDWebServerResponse * _Nullable(__kindof GCDWebServerDataRequest * _Nonnull request) {
        
        NSDictionary *requestBody = [NSJSONSerialization JSONObjectWithData:[request data] options:0 error:nil];
        NSString *requestedDocument = requestBody[@"document_name"];
        if (!requestedDocument) {
            return responseError;
        }
        
        id document = getDocumentWithName(requestedDocument);
        if (!document) {
            return responseError;
        }

        id disassembledFile = ((id (*)(id, SEL))objc_msgSend)(document, NSSelectorFromString(@"disassembledFile"));
        NSArray *segments = ((id (*)(id, SEL))objc_msgSend)(disassembledFile, NSSelectorFromString(@"segments"));
        
        NSMutableArray *segmentNames = [[NSMutableArray alloc] init];
        for (id segment in segments) {
            NSString *segmentName = ((id (*)(id, SEL))objc_msgSend)(segment, NSSelectorFromString(@"segmentName"));
            [segmentNames addObject:segmentName];
        }
        
        return [GCDWebServerDataResponse responseWithJSONObject:segmentNames];
    }];
    
    [webServer addHandlerForMethod:@"POST" path:@"/procedures" requestClass:[GCDWebServerDataRequest class] processBlock:^GCDWebServerResponse * _Nullable(__kindof GCDWebServerDataRequest * _Nonnull request) {
        
        NSDictionary *requestBody = [NSJSONSerialization JSONObjectWithData:[request data] options:0 error:nil];
        NSString *requestedDocument = requestBody[@"document_name"];
        if (!requestedDocument) {
            return responseError;
        }
        
        id document = getDocumentWithName(requestedDocument);
        if (!document) {
            return responseError;
        }

        id disassembledFile = ((id (*)(id, SEL))objc_msgSend)(document, NSSelectorFromString(@"disassembledFile"));
        NSArray *allNamedAddresses = ((id (*)(id, SEL))objc_msgSend)(disassembledFile, NSSelectorFromString(@"allNamedAddresses"));
        
        NSMutableArray *response = [[NSMutableArray alloc] init];
        for (id address in allNamedAddresses) {
            
            NSString *demangledName = ((id (*)(id, SEL, int64_t))objc_msgSend)(disassembledFile, NSSelectorFromString(@"demangledNameForVirtualAddress:"), [address unsignedLongLongValue]);
            NSDictionary *namedEntry = @{
                @"address": @([address unsignedLongLongValue]),
                @"label": demangledName,
            };
            [response addObject:namedEntry];
        }
        
        
        
        return [GCDWebServerDataResponse responseWithJSONObject:response];
    }];
    
    
    [webServer addHandlerForMethod:@"POST" path:@"/decompile" requestClass:[GCDWebServerDataRequest class] processBlock:^GCDWebServerResponse * _Nullable(__kindof GCDWebServerDataRequest * _Nonnull request) {
        
        NSDictionary *requestBody = [NSJSONSerialization JSONObjectWithData:[request data] options:0 error:nil];
        NSString *requestedDocument = requestBody[@"document_name"];
        NSString *procedureAddress = requestBody[@"procedure_address"];
        if (!requestedDocument || !procedureAddress) {
            return responseError;
        }
        
        id document = getDocumentWithName(requestedDocument);
        if (!document) {
            return responseError;
        }

        id disassembledFile = ((id (*)(id, SEL))objc_msgSend)(document, NSSelectorFromString(@"disassembledFile"));
        id procedure = ((id (*)(id, SEL, uint64_t))objc_msgSend)(disassembledFile, NSSelectorFromString(@"procedureAt:"), [procedureAddress longLongValue]);
        if (!procedure) {
            return responseError;
        }
        
        id pseudoCode = ((id (*)(id, SEL))objc_msgSend)(procedure, NSSelectorFromString(@"completePseudoCode"));
        NSString *pseudoCodeString = ((id (*)(id, SEL))objc_msgSend)(pseudoCode, NSSelectorFromString(@"string"));

        return [GCDWebServerDataResponse responseWithJSONObject:@{@"data": pseudoCodeString}];
    }];
    
    
    [webServer addHandlerForMethod:@"POST" path:@"/disassemble" requestClass:[GCDWebServerDataRequest class] processBlock:^GCDWebServerResponse * _Nullable(__kindof GCDWebServerDataRequest * _Nonnull request) {
        
        NSDictionary *requestBody = [NSJSONSerialization JSONObjectWithData:[request data] options:0 error:nil];
        NSString *requestedDocument = requestBody[@"document_name"];
        NSString *procedureAddress = requestBody[@"procedure_address"];
        if (!requestedDocument || !procedureAddress) {
            return responseError;
        }
        
        id document = getDocumentWithName(requestedDocument);
        if (!document) {
            return responseError;
        }

        id disassembledFile = ((id (*)(id, SEL))objc_msgSend)(document, NSSelectorFromString(@"disassembledFile"));
        id procedure = ((id (*)(id, SEL, uint64_t))objc_msgSend)(disassembledFile, NSSelectorFromString(@"procedureAt:"), [procedureAddress longLongValue]);
        if (!procedure) {
            return responseError;
        }
        
        NSMutableString *procedureAssemblyText = [[NSMutableString alloc] init];

        NSArray *basicBlocks = ((id (*)(id, SEL))objc_msgSend)(procedure, NSSelectorFromString(@"basicBlocks"));
        for (id basicBlock in basicBlocks) {
            
            uint64_t instrCursor = ((uint64_t (*)(id, SEL))objc_msgSend)(basicBlock, NSSelectorFromString(@"from"));
            uint64_t basicBlockEndAddress = ((uint64_t (*)(id, SEL))objc_msgSend)(basicBlock, NSSelectorFromString(@"to"));
            
            id containingSegment = ((id (*)(id, SEL, uint64_t))objc_msgSend)(disassembledFile, NSSelectorFromString(@"segmentForVirtualAddress:"), instrCursor);
            while (instrCursor <= basicBlockEndAddress) {
                
                NSArray *asmLines = ((id (*)(id, SEL, uint64_t, BOOL, BOOL, BOOL, BOOL, BOOL))objc_msgSend)(containingSegment, NSSelectorFromString(@"stringsForVirtualAddress:includingDecorations:inlineComments:addressField:hexColumn:compactMode:"), instrCursor, YES, YES, YES, NO, NO);
                
                for (id asmLine in asmLines) {
                    NSString *assemblyLineText = ((id (*)(id, SEL))objc_msgSend)(asmLine, NSSelectorFromString(@"string"));
                    [procedureAssemblyText appendString:assemblyLineText];
                    [procedureAssemblyText appendString:@"\n"];
                }
                
                instrCursor += ((uint64_t (*)(id, SEL, uint64_t))objc_msgSend)(containingSegment, NSSelectorFromString(@"getByteLengthAtVirtualAddress:"), instrCursor);
            }
        }
        
        return [GCDWebServerDataResponse responseWithJSONObject:@{@"data": procedureAssemblyText}];
    }];
    
    [webServer addHandlerForMethod:@"POST" path:@"/filepath" requestClass:[GCDWebServerDataRequest class] processBlock:^GCDWebServerResponse * _Nullable(__kindof GCDWebServerDataRequest * _Nonnull request) {
        
        NSDictionary *requestBody = [NSJSONSerialization JSONObjectWithData:[request data] options:0 error:nil];
        NSString *requestedDocument = requestBody[@"document_name"];
        if (!requestedDocument) {
            return responseError;
        }
        
        id document = getDocumentWithName(requestedDocument);
        if (!document) {
            return responseError;
        }

        id disassembledFile = ((id (*)(id, SEL))objc_msgSend)(document, NSSelectorFromString(@"disassembledFile"));
        NSString *filePath = ((id (*)(id, SEL))objc_msgSend)(disassembledFile, NSSelectorFromString(@"originalFilePath"));

        return [GCDWebServerDataResponse responseWithJSONObject:@{@"data": filePath}];
    }];
    
    
    [webServer addHandlerForMethod:@"POST" path:@"/terminate" requestClass:[GCDWebServerDataRequest class] processBlock:^GCDWebServerResponse * _Nullable(__kindof GCDWebServerDataRequest * _Nonnull request) {
        
        exit(0);

        return [GCDWebServerDataResponse responseWithJSONObject:@{@"data": @"success"}];
    }];
    
    [webServer startWithPort:8080 bonjourName:nil];
}
