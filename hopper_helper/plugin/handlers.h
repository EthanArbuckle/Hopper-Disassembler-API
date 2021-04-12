//
//  handlers.h
//  hopper_helper
//
//  Created by Ethan Arbuckle on 4/12/21.
//

#ifndef handlers_h
#define handlers_h

#import "GCDWebServerDataResponse.h"


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

#endif /* handlers_h */
