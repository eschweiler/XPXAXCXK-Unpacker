/* ============================================================================
* Copyright (c) 2012, Sebastian Eschweiler <advanced(dot)malware<dot>analyst[at]gmail.com>
* All rights reserved.
* 
* Redistribution and use in source and binary forms, with or without
* modification, are permitted provided that the following conditions are met:
*     * Redistributions of source code must retain the above copyright
*       notice, this list of conditions and the following disclaimer.
*     * Redistributions in binary form must reproduce the above copyright
*       notice, this list of conditions and the following disclaimer in the
*       documentation and/or other materials provided with the distribution.
*     * Neither the name of the <organization> nor the
*       names of its contributors may be used to endorse or promote products
*       derived from this software without specific prior written permission.
* 
* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
* ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
* WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
* DISCLAIMED. IN NO EVENT SHALL <COPYRIGHT HOLDER> BE LIABLE FOR ANY
* DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
* (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
* LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
* ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
* (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
* SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
* =============================================================================
*/

#include "Base64.h"
#include <string.h>
#include <Windows.h>

// from http://stackoverflow.com/questions/342409/how-do-i-base64-encode-decode-in-c

static const char  table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";


bool isbase64(char c)
{
	return c && strchr(table, c) != NULL;
}


inline char value(char c)
{
	const char *p = strchr(table, c);
	if(p) {
		return p-table;
	} else {
		return 0;
	}
}


int UnBase64(unsigned char *dest, const unsigned char *src, int srclen)
{
	*dest = 0;
	if(*src == 0) 
	{
		return 0;
	}
	unsigned char *p = dest;
	do
	{

		char a = value(src[0]);
		char b = value(src[1]);
		char c = value(src[2]);
		char d = value(src[3]);
		*p++ = (a << 2) | (b >> 4);
		*p++ = (b << 4) | (c >> 2);
		*p++ = (c << 6) | d;
		if(!isbase64(src[1])) 
		{
			p -= 2;
			break;
		} 
		else if(!isbase64(src[2])) 
		{
			p -= 2;
			break;
		} 
		else if(!isbase64(src[3])) 
		{
			p--;
			break;
		}
		src += 4;
		while(*src && (*src == 13 || *src == 10)) src++;
	}
	while(srclen-= 4);
	*p = 0;
	return p-dest;
}


ustring base64Decode(const ustring& base64Data)
{
	unsigned char* tmpBinData = new unsigned char[base64Data.length()/8*6 + 16];
	int len = UnBase64(tmpBinData, base64Data.c_str(), base64Data.length());
	ustring binData(tmpBinData, len);
	delete[] tmpBinData;

	return binData;
}