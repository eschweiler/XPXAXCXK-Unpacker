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

#include <gtest/gtest.h>
#include <CryptAnalyzer.h>
#include <tchar.h>

#include <fstream>
#include <streambuf>

#include <common.h>

using namespace std;

class CryptAnalyzerTest : public ::testing::Test
{

public:
	CryptAnalyzerTest()
	{}

	virtual ~CryptAnalyzerTest()
	{}

	virtual void SetUp()
	{}

	virtual void TearDown()
	{}

};


TEST_F(CryptAnalyzerTest, emptyTest)
{
	Histogram<char, string::const_iterator> h;
	ASSERT_EQ(h.getNumberOfElements(), 0);
}


TEST_F(CryptAnalyzerTest, testOneElement)
{
	Histogram<char, string::const_iterator> h;
	string data("a");
	h.addData(data.begin(), data.end());
	ASSERT_EQ(h.getNumberOfElements(), 1);
}


TEST_F(CryptAnalyzerTest, testOneElementMultipleTimes)
{
	Histogram<char, string::const_iterator> h;
	string data("aaaaaaaaaa");
	h.addData(data.begin(), data.end());
	ASSERT_EQ(h.getNumberOfElements(), 1);
}


TEST_F(CryptAnalyzerTest, testTwoElementsOneTime)
{
	Histogram<char, string::const_iterator> h;
	string data("ab");
	h.addData(data.begin(), data.end());
	ASSERT_EQ(h.getNumberOfElements(), 2);
}


TEST_F(CryptAnalyzerTest, testTwoElementsMultipleTimes)
{
	Histogram<char, string::const_iterator> h;
	string data("aaabababbbababaaabbbbbababababaabbbabab");
	h.addData(data.begin(), data.end());
	ASSERT_EQ(h.getNumberOfElements(), 2);
}




TEST_F(CryptAnalyzerTest, testDetectModulus1)
{
	basic_ifstream<unsigned char> t("testfiles/d5b0a448f59c3e946255333ad0ef5cc5/dechunked.bin", ios::binary);
	ustring s((istreambuf_iterator<unsigned char>(t)), istreambuf_iterator<unsigned char>());

	CryptAnalyzer m;
	unsigned char mod = m.calculateFirstRoundModulus(s.substr(0, 1024));

	ASSERT_EQ(mod, 0x5a);

}



TEST_F(CryptAnalyzerTest, testDetectModulus2)
{
	basic_ifstream<unsigned char> t("testfiles/427b7b708de8436d73cbbfd645099416/1dechunked.bin", ios::binary);
	ustring s((istreambuf_iterator<unsigned char>(t)), istreambuf_iterator<unsigned char>());

	CryptAnalyzer m;
	unsigned char mod = m.calculateFirstRoundModulus(s.substr(0, 1024));

	ASSERT_EQ(mod, 0x2c);
}


TEST_F(CryptAnalyzerTest, testDetectOffset1)
{
	basic_ifstream<unsigned char> t("testfiles/427b7b708de8436d73cbbfd645099416/1dechunked.bin", ios::binary);
	ustring s((istreambuf_iterator<unsigned char>(t)), istreambuf_iterator<unsigned char>());

	CryptAnalyzer m;
	ustring modded = m.minusMod(s.substr(0, 1024), 0x2c);
	
	unsigned char offset = m.calculateFirstRoundOffset(modded);

	ASSERT_EQ(offset, 0xCB);
}


TEST_F(CryptAnalyzerTest, testDetectOffset2)
{
	basic_ifstream<unsigned char> t("testfiles/d5b0a448f59c3e946255333ad0ef5cc5/dechunked.bin", ios::binary);
	ustring s((istreambuf_iterator<unsigned char>(t)), istreambuf_iterator<unsigned char>());

	CryptAnalyzer m;
	ustring modded = m.minusMod(s.substr(0, 1024), 0x5a);

	unsigned char offset = m.calculateFirstRoundOffset(modded);

	ASSERT_EQ(offset, 0);
}


TEST_F(CryptAnalyzerTest, testDetectOffsetZero)
{
	ustring base64((const unsigned char*)"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/");
	CryptAnalyzer m;
	unsigned char offset = m.calculateFirstRoundOffset(base64);

	ASSERT_EQ(offset, 0);
}


TEST_F(CryptAnalyzerTest, testmakeBase64List)
{
	string base64("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/");
	
	vector<bool> correctVector(256);
	for (string::const_iterator i = base64.begin(); i != base64.end(); i++)
		correctVector[*i] = true;

	list<bool> correctList(correctVector.begin(), correctVector.end());

	CryptAnalyzer m;
	list<bool> myList = m.makeBase64List();

	ASSERT_EQ(correctList, myList);
}


TEST_F(CryptAnalyzerTest, testDetectInvalidOffset)
{
	ustring base64Plus1((const unsigned char*) "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/?");

	CryptAnalyzer m;
	ASSERT_THROW(m.calculateFirstRoundOffset(base64Plus1), exception);

}


TEST_F(CryptAnalyzerTest, testXor)
{
	ustring data((unsigned char*)"hello world");
	CryptAnalyzer m;

	ustring output = m.xor(data, 0);
	ASSERT_EQ(data, output);

	output = m.xor(data, 0x11);
	ustring realXorData((unsigned char*)"yt}}~1f~c}u");
	ASSERT_EQ(realXorData, output);

}


TEST_F(CryptAnalyzerTest, testCalculateSecondRoundXorValue)
{
	unsigned char input[16] = {
	0xA3, 0xAB, 0xA3, 0xBA, 0xA3, 0xB8, 0xA3, 0xB0, 0x7B, 0xA9, 0x78, 0x7B,
	0x4A, 0x0A, 0x7A, 0x7B
	};

	
	CryptAnalyzer m;
	list<unsigned char> xorValues = m.calculateSecondRoundXorValue(input);
	unsigned char realValues[16] = {'\x1B', '\x1F', ';', '?', '[', '_', '{', '\x7F', '\x9B', '\x9F', '\xBB', '\xBF', '\xDB', '\xDF', '\xFB', '\xFF'};
	list<unsigned char> realValuesList;
	realValuesList.assign(realValues, realValues + sizeof realValues);

	ASSERT_EQ(xorValues, realValuesList);

}


TEST_F(CryptAnalyzerTest, testCalculateSecondRoundOffset)
{
	unsigned char input[16] = {
		0xA3, 0xAB, 0xA3, 0xBA, 0xA3, 0xB8, 0xA3, 0xB0, 0x7B, 0xA9, 0x78, 0x7B,
		0x4A, 0x0A, 0x7A, 0x7B
	};
	CryptAnalyzer m;

	unsigned char offset = m.calculateSecondRoundOffset(input, 0x1b);

	ASSERT_EQ(offset, 0x60);

	ASSERT_EQ((0x1b ^ input[0]) - offset, 'X');
	ASSERT_EQ((0x1b ^ input[1]) - offset, 'P');
	ASSERT_EQ((0x1b ^ input[2]) - offset, 'X');
	ASSERT_EQ((0x1b ^ input[3]) - offset, 'A');
	ASSERT_EQ((0x1b ^ input[4]) - offset, 'X');
	ASSERT_EQ((0x1b ^ input[5]) - offset, 'C');
	ASSERT_EQ((0x1b ^ input[6]) - offset, 'X');
	ASSERT_EQ((0x1b ^ input[7]) - offset, 'K');

}
