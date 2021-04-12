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

    return objcInvoke(disassembledFile, @"allStrings");
};


// List all segments in a document
HandlerBlock SegmentsHandler = ^id(NSDictionary *requestData, id hopperDocument, id disassembledFile) {
    
    if (!disassembledFile) {
        return nil;
    }

    NSArray *segments = objcInvoke(disassembledFile, @"segments");
    
    NSMutableArray *segmentNames = [[NSMutableArray alloc] init];
    for (id segment in segments) {
        NSString *segmentName = objcInvoke(segment, @"segmentName");
        [segmentNames addObject:segmentName];
    }
    
    return segmentNames;
};


// List all procedures in a document
HandlerBlock ProceduresHandler = ^id(NSDictionary *requestData, id hopperDocument, id disassembledFile) {
    
    if (!disassembledFile) {
        return nil;
    }

    NSArray *allNamedAddresses = objcInvoke(disassembledFile, @"allNamedAddresses");
    
    NSMutableArray *response = [[NSMutableArray alloc] init];
    for (id address in allNamedAddresses) {
        
        NSString *demangledName = objcInvoke_1(disassembledFile, @"demangledNameForVirtualAddress:", [address longLongValue]);
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
    
    id procedure = objcInvoke_1(disassembledFile, @"procedureAt:", [procedureAddress longLongValue]);
    if (!procedure) {
        return nil;
    }
    
    id pseudoCode = objcInvoke(procedure, @"completePseudoCode");
    NSString *pseudoCodeString = objcInvoke(pseudoCode, @"string");

    return pseudoCodeString;
};


// Get assembly text for a specified function start address
HandlerBlock DisassembleHandler = ^id(NSDictionary *requestData, id hopperDocument, id disassembledFile) {
    
    NSString *procedureAddress = requestData[@"procedure_address"];
    if (!disassembledFile || !procedureAddress) {
        return nil;
    }

    id procedure = objcInvoke_1(disassembledFile, @"procedureAt:", [procedureAddress longLongValue]);
    if (!procedure) {
        return nil;
    }
    NSArray *basicBlocks = objcInvoke(procedure, @"basicBlocks");
    id containingSegment = objcInvoke_1(disassembledFile, @"segmentForVirtualAddress:", [procedureAddress longLongValue]);
    
    NSMutableString *procedureAssemblyText = [[NSMutableString alloc] init];
    for (id basicBlock in basicBlocks) {
        
        uint64_t instrCursor = objcInvokeT(basicBlock, @"from", uint64_t);
        uint64_t basicBlockEndAddress = objcInvokeT(basicBlock, @"to", uint64_t);
        while (instrCursor <= basicBlockEndAddress) {
            
            NSArray *asmLines = ((id (*)(id, SEL, uint64_t, BOOL, BOOL, BOOL, BOOL, BOOL))objc_msgSend)(containingSegment, NSSelectorFromString(@"stringsForVirtualAddress:includingDecorations:inlineComments:addressField:hexColumn:compactMode:"), instrCursor, YES, YES, YES, NO, NO);
            
            for (id asmLine in asmLines) {
                NSString *assemblyLineText = objcInvoke(asmLine, @"string");
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

    return objcInvoke(disassembledFile, @"originalFilePath");
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
    
    id procedure = objcInvoke_1(disassembledFile, @"procedureAt:", [procedureAddress longLongValue]);
    if (!procedure) {
        return nil;
    }
    
    id signaturePseudoCode = objcInvoke(procedure, @"signaturePseudoCode");
    return objcInvoke(signaturePseudoCode, @"string");
};


// Query status of a Document's analysis
HandlerBlock StatusHandler = ^id(NSDictionary *requestData, id hopperDocument, id disassembledFile) {
    
    if (!disassembledFile) {
        return nil;
    }

    BOOL activeAnalysis = objcInvokeT(disassembledFile, @"analysisInProgress", BOOL);
    return @{@"analysis_active": @(activeAnalysis)};
};


// List cross-references to a specified address
HandlerBlock XrefsHandler = ^id(NSDictionary *requestData, id hopperDocument, id disassembledFile) {
    
    NSString *procedureAddress = requestData[@"procedure_address"];
    if (!disassembledFile || !procedureAddress) {
        return nil;
    }
    
    uint64_t address = [procedureAddress longLongValue];
    id containingSegment = objcInvoke_1(disassembledFile, @"segmentForVirtualAddress:", address);
    id xrefAsmLine = objcInvoke_1(containingSegment, @"formatXREFStringForAddress:", address);
    return objcInvoke(xrefAsmLine, @"string");
};


// Get all the log messages in the Log view for a document
HandlerBlock LogMessagesHandler = ^id(NSDictionary *requestData, id hopperDocument, id disassembledFile) {
    
    if (!disassembledFile) {
        return nil;
    }
    
    id logView = objcInvoke(hopperDocument, @"logView");
    return objcInvoke(logView, @"string");
};
