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

#include "XPackUnpacker.h"

/* // original code
void __stdcall XPackUnpacker::revxealPackedCode(unsigned char* buffer, DWORD len)
{
DWORD counter;
unsigned char* packedExe;
__asm
{
push esi
push ebx
mov     eax, [buffer]
mov     [packedExe], eax
mov     eax, [len]
xor     edx, edx
test    eax, eax
jz      short loc_40156F

loc_4014F5:                             
and     [counter], 0

loc_4014F9:                             
mov     ecx, [len]
sub     ecx, [counter]
push    10h
sub     ecx, edx
pop     eax
cmp     ecx, eax
ja      short loc_401510
mov     eax, [len]
sub     eax, [counter]
sub     eax, edx

loc_401510:                             
cmp     [counter], eax
jnb     short loc_40153F
mov     esi, [packedExe]
add     esi, [counter]
mov     cl, dl
add     cl, byte ptr [counter]
mov     eax, edx
shr     eax, 4
mov     bl, cl
and     al, 3
and     bl, 1Fh
imul    bl
and     cl, 3
imul    cl
mov     cl, 0FEh
sub     cl, al
add     [esi+edx], cl
inc     [counter]
jmp     short loc_4014F9

loc_40153F:                             
xor     ecx, ecx                        

loc_401541:                             
mov     esi, [len]
sub     esi, ecx
push    8
sub     esi, edx
pop     eax
cmp     esi, eax
ja      short loc_401556
mov     eax, [len]
sub     eax, ecx
sub     eax, edx

loc_401556:                             
cmp     ecx, eax
jnb     short loc_401565
mov     eax, [packedExe]
add     eax, ecx
sub     [eax+edx], cl
inc     ecx
jmp     short loc_401541


loc_401565:                             
mov     eax, [len]
add     edx, 40h
cmp     edx, eax
jb      short loc_4014F5
loc_40156F:
pop ebx
pop esi
}

}
*/


void XPackUnpacker::decryptStage2a(unsigned char *buffer, DWORD len)
{
	unsigned int currentBlock = 0;

	if ( !len )
		return;

	do
	{
		for (size_t i = 0; i < 16 && i + currentBlock < len; i++)
			buffer[i + currentBlock] += -2 - ((i + currentBlock) & 3) * ((i + currentBlock) & 0x1F) * ((currentBlock >> 4) & 3);
		
		for (size_t i = 0; i < 8 && i + currentBlock < len; i++)
			buffer[i + currentBlock] -= i;

		currentBlock += 64;

	}
	while ( currentBlock < len );
}


void XPackUnpacker::decryptStage2a( ustring& s )
{
	decryptStage2a(const_cast<unsigned char*>(s.c_str()), s.length());
}


void XPackUnpacker::decryptFirstRound( ustring& s, const unsigned char offset, const unsigned char modulus )
{
	for (size_t i = 0; i < s.length(); i++)
		s[i] += offset - (i % modulus);
}


void XPackUnpacker::decryptFirstRound( ustring& assembledData )
{
	ustring assembledDataSnippet = assembledData.substr(0, 1024);
	unsigned char modulus = CryptAnalyzer::calculateFirstRoundModulus(assembledDataSnippet);
	ustring modded = CryptAnalyzer::minusMod(assembledDataSnippet, modulus);
	unsigned char offsetFirstRound = CryptAnalyzer::calculateFirstRoundOffset(modded);

	decryptFirstRound(assembledData, offsetFirstRound, modulus);

}


void XPackUnpacker::decryptStage2b( ustring& s, const unsigned char xorValue, const unsigned char offset )
{
	for (ustring::iterator i = s.begin(); i != s.end(); i++)
		*i = (*i ^ xorValue) - offset;
}


ustring XPackUnpacker::assemble( const ustring& s )
{
	vector<Chunk*> heads = ChunkAssembler::getChunkHeads(s);

	if (heads.size() == 0)
		throw exception("Error: could not find any chunks!");

	return ChunkAssembler::assemble(s, heads);
}


ustring XPackUnpacker::secondRoundAndDecompress( const ustring& xpackData )
{
	ustring xpackHeader = xpackData.substr(0, 16);
	list<pair<unsigned char, unsigned char>> cryptoValues = CryptAnalyzer::calculateSecondRoundOffset(xpackHeader, CryptAnalyzer::calculateSecondRoundXorValue(xpackHeader));

	for (list<pair<unsigned char, unsigned char>>::const_iterator i = cryptoValues.begin(); i != cryptoValues.end(); i++)
	{
		ustring tmpXpackData = xpackData;
		decryptStage2b(tmpXpackData, i->first, i->second);

		XpackStruct* d = (XpackStruct*) tmpXpackData.c_str();
		if (d->compressedLength != tmpXpackData.length() - 0x10)
			continue;

		ustring decompressedData = d->decompress();
		if (decompressedData.length() == d->decompressedLength)
			return decompressedData;
	}

	throw exception("Could not decompress data");

}


bool XPackUnpacker::isPackedByXpack( const ustring& s )
{
	Chunk* chunk = ChunkAssembler::getFirstChunk(s);

	return (chunk != NULL);

}


ustring XPackUnpacker::unpack( const ustring& s )
{
	ustring assembledData = assemble(s);
	decryptFirstRound(assembledData);

	ustring xpackData = base64Decode(assembledData);

	decryptStage2a(xpackData);

	return secondRoundAndDecompress(xpackData);

}
