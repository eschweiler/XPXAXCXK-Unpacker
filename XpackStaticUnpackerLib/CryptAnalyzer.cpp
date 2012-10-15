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

#include "CryptAnalyzer.h"
#include "Base64.h"

CryptAnalyzer::CryptAnalyzer()
{}


CryptAnalyzer::~CryptAnalyzer()
{}


ustring CryptAnalyzer::minusMod(const ustring& input, const unsigned char mod)
{
	ustring res = input;

	for (size_t i = 0; i < res.length(); i++)
		res[i] -= i % mod;
	
	return res;

}


ustring CryptAnalyzer::xor(const ustring& input, const unsigned char value)
{
	ustring res = input;

	for (ustring::iterator i = res.begin(); i != res.end(); i++)
		*i ^= value;

	return res;

}


unsigned char CryptAnalyzer::calculateFirstRoundModulus(const ustring& data )
{
	pair<unsigned char, unsigned char> minMod(0xFF, 0);

	for (unsigned char mod = 2; mod < 0xFF; mod++)
	{
		ustring tmpData = minusMod(data, mod);
		Histogram<unsigned char, ustring::const_iterator> histo;
		histo.addData(tmpData.begin(), tmpData.end());

		if (histo.getNumberOfElements() < minMod.first)
			minMod = pair<unsigned char, unsigned char>(histo.getNumberOfElements(), mod);

	}

	if (minMod.first > 65)
		throw exception("Could not find proper modulus");

	return minMod.second;

}

list<bool> CryptAnalyzer::makeBase64List()
{
	list<bool> base64list;

	for (size_t i = 0; i < 256; i++)
		base64list.push_back(isbase64((char) i));

	return base64list;

}


unsigned char CryptAnalyzer::calculateFirstRoundOffset(const ustring& data)
{

	list<bool> base64list = makeBase64List();
	list<bool> datalist;

	Histogram<unsigned char, ustring::const_iterator> histo;
	histo.addData(data.begin(), data.end());

	for (size_t i = 0; i < 256; i++)
		datalist.push_back(histo.getHisto()[i] > 0);

	// rotate the list until correct offset is found
	for (size_t i = 0; i < 256; i++)
	{
		if (datalist == base64list)
			return i;
		datalist.push_front(datalist.back());
		datalist.pop_back();
	}

	throw exception("Could not find proper offset");
}


list<unsigned char> CryptAnalyzer::calculateSecondRoundXorValue(const ustring& data)
{
	list<unsigned char> res;

	for (size_t i = 0; i < 256; i++)
	{
		ustring tmpData = xor(data, (unsigned char) i);
		if (tmpData[0] - tmpData[1]== 'X' - 'P' && tmpData[1] - tmpData[2]== 'P' - 'X' && 
			tmpData[2] - tmpData[3]== 'X' - 'A' && tmpData[3] - tmpData[4]== 'A' - 'X' && 
			tmpData[4] - tmpData[5]== 'X' - 'C' && tmpData[5] - tmpData[6]== 'C' - 'X' && 
			tmpData[6] - tmpData[7]== 'X' - 'K' 
			)

			res.push_back((unsigned char)i);
	}

	if (res.size() == 0)
		throw exception("Could not find proper XOR value");

	return res;

}


unsigned char CryptAnalyzer::calculateSecondRoundOffset( const ustring& data, const unsigned char xor_value )
{
	return (data[0] ^ xor_value) - 'X';
	
}

list<pair<unsigned char, unsigned char>> CryptAnalyzer::calculateSecondRoundOffset( const ustring& data, const list<unsigned char>& xor_value )
{
	list<pair<unsigned char, unsigned char>> res;

	for (list<unsigned char>::const_iterator i = xor_value.begin(); i != xor_value.end(); i++)
		res.push_back(pair<unsigned char, unsigned char>(*i, calculateSecondRoundOffset(data, *i)));

	return res;
}
