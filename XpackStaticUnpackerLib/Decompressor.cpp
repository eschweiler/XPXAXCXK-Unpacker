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

#include "Decompressor.h"


__declspec(naked) int __stdcall decompressAsm(unsigned char* dictionary, const unsigned char* compressedBuffer, ULONG compressedLength, ULONG* someValue, unsigned char* decompressedBuffer, ULONG decompressedLength, ULONG* someValue2)
{
	__asm{
		push    edi
			push    esi
			push    ebx
			push    ebp
			mov     ebp, esp
			mov     eax, [ebp+24h]
		add     [ebp+28h], eax
			push    eax
			cld
			mov     esi, [ebp+18h]
		add     [ebp+1Ch], esi
			push    esi
			mov     esi, [ebp+14h]
		lodsd
			xchg    eax, edx
			push    edx
			mov     cl, [esi-2]
		or      eax, 0FFFFFFFFh
			shl     eax, cl
			not     eax
			push    eax
			mov     cl, dh
			or      eax, 0FFFFFFFFh
			shl     eax, cl
			not     eax
			push    eax
			add     cl, dl
			mov     edi, esi
			sub     esp, 0Ch
			sub     eax, eax
			inc     eax
			push    eax
			push    eax
			push    eax
			push    eax
			push    eax
			push    edi
			sub     esi, esi
			push    esi
			or      ebx, 0FFFFFFFFh
			mov     eax, 300h
			shl     eax, cl
			lea     ecx, [eax+736h]
		mov     eax, 4000400h
			shr     ecx, 1
			rep stosd
			push    5
			pop     ecx
loc_401962:
		call    unpack_1
			loop    loc_401962
			lea     esi, [esi]
		lea     edi, [edi]
loc_40196D:
		mov     edi, [ebp-4]
		mov     eax, [ebp-10h]
		sub     edi, [ebp+24h]
		and     eax, edi
			mov     [ebp-18h], eax
			mov     al, 0
			call    unpack_2
			jnz     loc_401A1D
			mov     cl, [ebp-0Ch]
		and     edi, [ebp-14h]
		shl     edi, cl
			sub     cl, 8
			neg     cl
			shr     esi, cl
			pop     eax
			add     edi, esi
			pop     esi
			lea     edi, [edi+edi*2]
		shl     edi, 8
			cmp     al, 7
			pop     edx
			lea     ecx, [esi+edi*2+3692]
		push    ecx
			push    esi
			mov     esi, 100h
			push    eax
			mov     al, 1
			jb      short loc_4019EB
			mov     edi, [ebp-4]
		sub     edi, [ebp-24h]
		movzx   edi, byte ptr [edi]
loc_4019C0:
		mov     ebp, [ebp-34h]
		shl     edi, 1
			mov     ecx, esi
			and     esi, edi
			add     ecx, esi
			lea     ebp, [ebp+ecx*2+0]
		call    unpack_4
			mov     ecx, eax
			shr     esi, 8
			and     ecx, 1
			cmp     esi, ecx
			mov     esi, 100h
			jnz     short loc_4019F3
			cmp     eax, esi
			jb      short loc_4019C0
			jmp     short loc_4019FF
loc_4019EB:
		mov     ebp, [ebp-34h]
		call    unpack_4
loc_4019F3:
		inc     eax
			inc     esi
			sub     eax, 1
			sub     esi, 1
			cmp     eax, esi
			jb      short loc_4019EB
loc_4019FF:
		pop     edx
			inc     edx
			cmp     edx, 5
			dec     edx
			mov     ecx, edx
			jb      short loc_401A18
			inc     edx
			cmp     edx, 0Bh
			dec     edx
			mov     cl, 4
			dec     cl
			jb      short loc_401A18
			mov     cl, 7
			dec     cl
loc_401A18:
		sub     edx, ecx
			push    edx
			jmp     short loc_401A6C
loc_401A1D:
		mov     al, 193
			dec     al
			call    unpack_6
			jnz     short loc_401A3C
			pop     eax
			pop     edi
			pop     edx
			pop     ecx
			pop     edx
			pop     ecx
			push    dword ptr [esp]
		push    ecx
			push    edx
			mov     edx, 664h
			mov     cl, 0
			jmp     short loc_401AAF
loc_401A3C:
		mov     al, 0CDh
			dec     al
			call    unpack_6
			jnz     short loc_401A75
			mov     al, 0F1h
			dec     al
			call    unpack_2
			jnz     short loc_401AA5
			pop     eax
			cmp     al, 7
			mov     al, 9
			jb      short loc_401A5B
			mov     al, 0Bh
loc_401A5B:
		push    eax
			mov     esi, [ebp-4]
		sub     esi, [ebp-24h]
		cmp     esi, [ebp+24h]
		jb      loc_401C3C
			lodsb
loc_401A6C:
		mov     edi, [ebp-4]
		stosb
			jmp     loc_401C03
loc_401A75:
		mov     al, 0D8h
			call    unpack_6
			mov     esi, [ebp-28h]
		jz      short loc_401A9C
			mov     al, 0E4h
			call    unpack_6
			mov     esi, [ebp-2Ch]
		jz      short loc_401A96
			mov     esi, [ebp-30h]
		mov     ecx, [ebp-2Ch]
		mov     [ebp-30h], ecx
loc_401A96:
		mov     ecx, [ebp-28h]
		mov     [ebp-2Ch], ecx
loc_401A9C:
		mov     ecx, [ebp-24h]
		mov     [ebp-28h], ecx
			mov     [ebp-24h], esi
loc_401AA5:
		pop     eax
			pop     edi
			pop     ecx
			mov     edx, 0A68h
			mov     cl, 8
loc_401AAF:
		add     edx, edi
			push    edx
			push    edi
			cmp     al, 7
			mov     al, cl
			jb      short loc_401ABB
			add     al, 3
loc_401ABB:
		push    eax
			mov     ebp, [ebp-34h]
		call    unpack_3
			jnz     short loc_401ADA
			mov     eax, [ebp-18h]
		mov     edi, [ebp-34h]
		shl     eax, 3
			sub     ecx, ecx
			push    8
			pop     esi
			lea     edi, [edi+eax*2+4]
		jmp     short loc_401B0F
loc_401ADA:
		mov     ebp, [ebp-34h]
		add     ebp, 2
			call    unpack_3
			jnz     short loc_401AFF
			mov     eax, [ebp-18h]
		mov     edi, [ebp-34h]
		shl     eax, 3
			push    8
			pop     ecx
			push    8
			pop     esi
			lea     edi, [edi+eax*2+104h]
		jmp     short loc_401B0F
loc_401AFF:
		mov     edi, 204h
			add     edi, [ebp-34h]
		push    10h
			pop     ecx
			mov     esi, 100h
loc_401B0F:
		mov     [ebp-1Ch], ecx
			sub     eax, eax
			inc     eax
loc_401B15:
		mov     ebp, edi
			call    unpack_4
			mov     ecx, eax
			sub     ecx, esi
			jb      short loc_401B15
			add     [ebp-1Ch], ecx
			cmp     dword ptr [ebp-3Ch], 4
			jnb     loc_401BDF
			add     dword ptr [ebp-3Ch], 7
			mov     ecx, [ebp-1Ch]
		cmp     ecx, 4
			jb      short loc_401B3E
			push    3
			pop     ecx
loc_401B3E:
		mov     edi, [ebp-38h]
		shl     ecx, 6
			sub     eax, eax
			inc     eax
			push    40h
			pop     esi
			lea     edi, [edi+ecx*2+360h]
loc_401B51:
		mov     ebp, edi
			call    unpack_4
			mov     ecx, eax
			sub     ecx, esi
			jb      short loc_401B51
			mov     [ebp-18h], ecx
			mov     [ebp-24h], ecx
			cmp     ecx, 4
			jb      short loc_401BDC
			mov     esi, ecx
			and     dword ptr [ebp-24h], 1
			shr     esi, 1
			or      dword ptr [ebp-24h], 2
			dec     esi
			cmp     ecx, 0Eh
			jnb     short loc_401B94
			mov     eax, 2AFh
			sub     eax, ecx
			mov     ecx, esi
			shl     byte ptr [ebp-24h], cl
			add     eax, [ebp-24h]
		shl     eax, 1
			add     eax, [ebp-38h]
		mov     [ebp-34h], eax
			jmp     short loc_401BC1
loc_401B94:
		sub     esi, 4
loc_401B97:
		call    unpack_5
			shr     ebx, 1
			shl     dword ptr [ebp-24h], 1
			cmp     [ebp-20h], ebx
			jb      short loc_401BAC
			inc     dword ptr [ebp-24h]
		sub     [ebp-20h], ebx
loc_401BAC:
		dec     esi
			jnz     short loc_401B97
			mov     eax, 644h
			add     eax, [ebp-38h]
		mov     [ebp-34h], eax
			shl     dword ptr [ebp-24h], 4
			push    4
			pop     esi
loc_401BC1:
		sub     edi, edi
			inc     edi
			mov     eax, edi
loc_401BC6:
		mov     ebp, [ebp-34h]
		call    unpack_4
			test    al, 1
			jz      short loc_401BD5
			or      [ebp-24h], edi
loc_401BD5:
		shl     edi, 1
			dec     esi
			jnz     short loc_401BC6
			jmp     short $+2
loc_401BDC:
		inc     dword ptr [ebp-24h]
loc_401BDF:
		mov     ecx, [ebp-1Ch]
		add     ecx, 2
			mov     edi, [ebp-4]
		mov     eax, edi
			sub     eax, [ebp+24h]
		cmp     [ebp-24h], eax
			ja      short loc_401C3C
			mov     esi, edi
			sub     esi, [ebp-24h]
		mov     edx, [ebp+28h]
loc_401BFA:
		lodsb
			stosb
			cmp     edi, edx
			jnb     short loc_401C03
			dec     ecx
			jnz     short loc_401BFA
loc_401C03:
		mov     [ebp-4], edi
			movzx   esi, al
			cmp     edi, [ebp+28h]
		jb      loc_40196D
			call    unpack_5
			sub     eax, eax
loc_401C19:
		lea     ebp, [esp+3Ch]
		mov     edx, [ebp+20h]
		mov     esi, [ebp-8]
		sub     esi, [ebp+18h]
		mov     [edx], esi
			mov     edx, [ebp+2Ch]
		mov     edi, [ebp-4]
		sub     edi, [ebp+24h]
		mov     [edx], edi
			leave
			pop     ebx
			pop     esi
			pop     edi
			retn    1Ch
loc_401C3A:
		pop     esi
loc_401C3B:
		pop     eax
loc_401C3C:
		sub     eax, eax
			inc     eax
			jmp     short loc_401C19

unpack_5:
		cmp     ebx, 1000000h
			jb      short loc_401C4A
			retn
loc_401C4A:
		shl     ebx, 8

unpack_1:
		push    esi
			mov     esi, [ebp-8]
		cmp     esi, [ebp+1Ch]
		jnb     short loc_401C3A
			mov     eax, [ebp-20h]
		shl     eax, 8
			lodsb
			mov     [ebp-20h], eax
			mov     [ebp-8], esi
			pop     esi
			retn

unpack_2:
		mov     ecx, [ebp-3Ch]
		movzx   eax, al
			shl     ecx, 4
			add     eax, [ebp-18h]
		add     eax, ecx
			jmp     short loc_401C7B

unpack_6:
		movzx   eax, al
			add     eax, [ebp-3Ch]
loc_401C7B:
		mov     ebp, [ebp-38h]
		lea     ebp, [ebp+eax*2+0]

unpack_3:
		sub     eax, eax

unpack_4:
		lea     ebp, [ebp+eax*2+0]
		cmp     ebx, 1000000h
			jnb     short loc_401CAC
			mov     ecx, [esp+38h]
		shl     dword ptr [esp+20h], 8
			cmp     ecx, [esp+5Ch]
		jnb     short loc_401C3B
			mov     dl, [ecx]
		inc     dword ptr [esp+38h]
		shl     ebx, 8
			mov     [esp+20h], dl
loc_401CAC:
		mov     ecx, ebx
			movzx   edx, word ptr [ebp+0]
		shr     ecx, 0Bh
			imul    ecx, edx
			cmp     [esp+20h], ecx
			jnb     short loc_401CD5
			mov     ebx, ecx
			mov     ecx, 800h
			sub     ecx, edx
			shr     ecx, 5
			add     [ebp+0], cx
			add     eax, eax
			lea     ebp, [esp+40h]
		retn
loc_401CD5:
		shr     edx, 5
			sub     [esp+20h], ecx
			sub     ebx, ecx
			sub     [ebp+0], dx
			add     eax, eax
			add     eax, 1
			lea     ebp, [esp+40h]
		retn

	};
}



ustring XpackStruct::decompress()
{
	if (!isValid())
		return ustring();

	unsigned char* dictionary = new unsigned char[decompressedLength];
	unsigned char* tmpDecompressedBuffer = new unsigned char[decompressedLength];

	ZeroMemory(dictionary, decompressedLength);
	dictionary[0] = 3;
	dictionary[2] = 2;

	ULONG bytesCompressedRead = 0;
	ULONG bytesUncompressedWritten = 0;

	int val = decompressAsm(dictionary, compressedBuffer, compressedLength, &bytesCompressedRead, tmpDecompressedBuffer, decompressedLength, &bytesUncompressedWritten);

	if (bytesCompressedRead != compressedLength)
		return ustring();

	ustring decompressedBuffer = ustring(tmpDecompressedBuffer, bytesUncompressedWritten);

	delete[] dictionary;
	delete[] tmpDecompressedBuffer;

	return decompressedBuffer;
}


