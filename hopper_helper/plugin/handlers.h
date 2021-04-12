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

extern HandlerBlock strings_handler;
extern HandlerBlock segments_handler;
extern HandlerBlock procedures_handler;
extern HandlerBlock decompile_handler;
extern HandlerBlock disassemble_handler;
extern HandlerBlock filepath_handler;
extern HandlerBlock terminate_handler;

#endif /* handlers_h */
