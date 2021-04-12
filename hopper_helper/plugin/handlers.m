//
//  handlers.m
//  pluginBackend
//
//  Created by Ethan Arbuckle on 4/12/21.
//

#import <Foundation/Foundation.h>
#import "handlers.h"
#include <objc/message.h>


// List all strings in a document
HandlerBlock StringsHandler = ^id(NSDictionary *requestData, id hopperDocument, id disassembledFile) {
    
    if (!disassembledFile) {
        return nil;
    }

    return ((id (*)(id, SEL))objc_msgSend)(disassembledFile, NSSelectorFromString(@"allStrings"));
};


// List all segments in a document
HandlerBlock SegmentsHandler = ^id(NSDictionary *requestData, id hopperDocument, id disassembledFile) {
    
    if (!disassembledFile) {
        return nil;
    }

    NSArray *segments = ((id (*)(id, SEL))objc_msgSend)(disassembledFile, NSSelectorFromString(@"segments"));
    
    NSMutableArray *segmentNames = [[NSMutableArray alloc] init];
    for (id segment in segments) {
        NSString *segmentName = ((id (*)(id, SEL))objc_msgSend)(segment, NSSelectorFromString(@"segmentName"));
        [segmentNames addObject:segmentName];
    }
    
    return segmentNames;
};


// List all procedures in a document
HandlerBlock ProceduresHandler = ^id(NSDictionary *requestData, id hopperDocument, id disassembledFile) {
    
    if (!disassembledFile) {
        return nil;
    }

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

    return response;
};


// Get pseudocode text for a specified function start address
HandlerBlock DecompileHandler = ^id(NSDictionary *requestData, id hopperDocument, id disassembledFile) {

    NSString *procedureAddress = requestData[@"procedure_address"];
    if (!disassembledFile || !procedureAddress) {
        return nil;
    }

    id procedure = ((id (*)(id, SEL, uint64_t))objc_msgSend)(disassembledFile, NSSelectorFromString(@"procedureAt:"), [procedureAddress longLongValue]);
    if (!procedure) {
        return nil;
    }
    
    id pseudoCode = ((id (*)(id, SEL))objc_msgSend)(procedure, NSSelectorFromString(@"completePseudoCode"));
    NSString *pseudoCodeString = ((id (*)(id, SEL))objc_msgSend)(pseudoCode, NSSelectorFromString(@"string"));

    return pseudoCodeString;
};


// Get assembly text for a specified function start address
HandlerBlock DisassembleHandler = ^id(NSDictionary *requestData, id hopperDocument, id disassembledFile) {
    
    NSString *procedureAddress = requestData[@"procedure_address"];
    if (!disassembledFile || !procedureAddress) {
        return nil;
    }

    id procedure = ((id (*)(id, SEL, uint64_t))objc_msgSend)(disassembledFile, NSSelectorFromString(@"procedureAt:"), [procedureAddress longLongValue]);
    if (!procedure) {
        return nil;
    }
    NSArray *basicBlocks = ((id (*)(id, SEL))objc_msgSend)(procedure, NSSelectorFromString(@"basicBlocks"));
    id containingSegment = ((id (*)(id, SEL, uint64_t))objc_msgSend)(disassembledFile, NSSelectorFromString(@"segmentForVirtualAddress:"), [procedureAddress longLongValue]);
    
    NSMutableString *procedureAssemblyText = [[NSMutableString alloc] init];
    for (id basicBlock in basicBlocks) {
        
        uint64_t instrCursor = ((uint64_t (*)(id, SEL))objc_msgSend)(basicBlock, NSSelectorFromString(@"from"));
        uint64_t basicBlockEndAddress = ((uint64_t (*)(id, SEL))objc_msgSend)(basicBlock, NSSelectorFromString(@"to"));
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
    
    return procedureAssemblyText;
};


// Get the executable path for a document
HandlerBlock FilePathHandler = ^id(NSDictionary *requestData, id hopperDocument, id disassembledFile) {
    
    if (!disassembledFile) {
        return nil;
    }

    return ((id (*)(id, SEL))objc_msgSend)(disassembledFile, NSSelectorFromString(@"originalFilePath"));
};


// Terminate Hopper (all documents)
HandlerBlock TerminateHandler = ^id(NSDictionary *requestData, id hopperDocument, id disassembledFile) {
    
    exit(0);
    return nil;
};


// Get the prettified function signature for a specified function start address
HandlerBlock ProcedureSignatureHandler = ^id(NSDictionary *requestData, id hopperDocument, id disassembledFile) {
    
    NSString *procedureAddress = requestData[@"procedure_address"];
    if (!disassembledFile || !procedureAddress) {
        return nil;
    }

    id procedure = ((id (*)(id, SEL, uint64_t))objc_msgSend)(disassembledFile, NSSelectorFromString(@"procedureAt:"), [procedureAddress longLongValue]);
    if (!procedure) {
        return nil;
    }
    
    id signaturePseudoCode = ((id (*)(id, SEL))objc_msgSend)(procedure, NSSelectorFromString(@"signaturePseudoCode"));
    return ((id (*)(id, SEL))objc_msgSend)(signaturePseudoCode, NSSelectorFromString(@"string"));
};


// Query status of a Document's analysis
HandlerBlock StatusHandler = ^id(NSDictionary *requestData, id hopperDocument, id disassembledFile) {
    
    if (!disassembledFile) {
        return nil;
    }

    BOOL activeAnalysis = ((BOOL (*)(id, SEL))objc_msgSend)(disassembledFile, NSSelectorFromString(@"analysisInProgress"));
    return @{@"analysis_active": @(activeAnalysis)};
};


// List cross-references to a specified address
HandlerBlock XrefsHandler = ^id(NSDictionary *requestData, id hopperDocument, id disassembledFile) {
    
    NSString *procedureAddress = requestData[@"procedure_address"];
    if (!disassembledFile || !procedureAddress) {
        return nil;
    }
    
    uint64_t address = [procedureAddress longLongValue];
    id containingSegment = ((id (*)(id, SEL, uint64_t))objc_msgSend)(disassembledFile, NSSelectorFromString(@"segmentForVirtualAddress:"), address);
    id xrefAsmLine = ((id (*)(id, SEL, uint64_t))objc_msgSend)(containingSegment, NSSelectorFromString(@"formatXREFStringForAddress:"), address);
    return ((id (*)(id, SEL))objc_msgSend)(xrefAsmLine, NSSelectorFromString(@"string"));
};


// Get all the log messages in the Log view for a document
HandlerBlock LogMessagesHandler = ^id(NSDictionary *requestData, id hopperDocument, id disassembledFile) {
    
    if (!disassembledFile) {
        return nil;
    }
    
    id logView = ((id (*)(id, SEL))objc_msgSend)(hopperDocument, NSSelectorFromString(@"logView"));
    return ((id (*)(id, SEL))objc_msgSend)(logView, NSSelectorFromString(@"string"));
};
