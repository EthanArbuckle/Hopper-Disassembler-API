//
//  handlers.h
//  hopper_helper
//
//  Created by Ethan Arbuckle on 4/12/21.
//

#ifndef handlers_h
#define handlers_h

#import "GCDWebServerDataResponse.h"

#define objcInvokeT(a, b, t) ((t (*)(id, SEL))objc_msgSend)(a, NSSelectorFromString(b))
#define objcInvoke(a, b) objcInvokeT(a, b, id)
#define objcInvoke_1(a, b, c) ((id (*)(id, SEL, typeof(c)))objc_msgSend)(a, NSSelectorFromString(b), c)


typedef id (^HandlerBlock)(NSDictionary *, id, id);

extern HandlerBlock StringsHandler;
extern HandlerBlock SegmentsHandler;
extern HandlerBlock ProceduresHandler;
extern HandlerBlock DecompileHandler;
extern HandlerBlock DisassembleHandler;
extern HandlerBlock FilePathHandler;
extern HandlerBlock TerminateHandler;
extern HandlerBlock ProcedureSignatureHandler;
extern HandlerBlock StatusHandler;
extern HandlerBlock XrefsHandler;
extern HandlerBlock LogMessagesHandler;
extern HandlerBlock AllPseudoCodeHandler;

#endif /* handlers_h */
