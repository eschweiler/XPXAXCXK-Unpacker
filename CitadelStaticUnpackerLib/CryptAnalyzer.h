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

#pragma once
#include <map>
#include <list>

#include <gtest/gtest_prod.h>

#include "common.h"

using namespace std;

template <class T, class Iterator>
class Histogram
{
public:
	Histogram(void)
	{}


	~Histogram(void)
	{}


	void addData(Iterator start, Iterator end)
	{
		for (start; start != end; start++)
		{
			histogram_[*start]++;
		}
	}


	size_t getNumberOfElements()
	{
		return histogram_.size();
	}

	map<T, size_t>& getHisto()
	{
		return histogram_;
	}


private:
	map<T, size_t> histogram_;
	
};



class CryptAnalyzer
{
public:
	CryptAnalyzer();
	~CryptAnalyzer();

	static unsigned char calculateFirstRoundModulus(const ustring& data);
	static unsigned char calculateFirstRoundOffset(const ustring& data);
	static list<unsigned char> calculateSecondRoundXorValue(const ustring& data);
	static list<pair<unsigned char, unsigned char>> calculateSecondRoundOffset( const ustring& data, const list<unsigned char>& xor_value );

	static ustring minusMod(const ustring& input, const unsigned char mod);

private:

	FRIEND_TEST(CryptAnalyzerTest, testmakeBase64List);
	FRIEND_TEST(CryptAnalyzerTest, testXor);
	FRIEND_TEST(CryptAnalyzerTest, testCalculateSecondRoundOffset);

	static unsigned char calculateSecondRoundOffset( const ustring& data, const unsigned char xor_value );

	static list<bool> makeBase64List();
	static ustring xor(const ustring& input, const unsigned char value);
};
