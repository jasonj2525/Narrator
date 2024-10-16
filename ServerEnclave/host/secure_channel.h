
/* Copyright (c) 2021 SUSTech University
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#ifndef SECURE_CHANNEL_H
#define SECURE_CHANNEL_H

#define CHANNEL_START           0
#define EXCHANGE_AES_KEY        1     
#define CHANNEL_DONE            2

/* The system setup process
Master ---------->  remote evidence ----------> slave 
Master <----------  remote evidence <---------- slave
Master ---------->  ASE pk and nonce ---------> slave 
Master <----------> ASE        reply <--------- slave 
Slave & Master System Init Done
*/

void secure_channel( );
#endif
