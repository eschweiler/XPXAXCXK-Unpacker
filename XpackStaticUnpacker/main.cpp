#include <stdio.h>
#include <stdlib.h>
#include <fstream>
#include <iostream>

#include <Decompressor.h>
#include <ChunkAssembler.h>
#include <XPackUnpacker.h>
#include <common.h>

using namespace std;

int main(int argc, char* argv[])
{

	cout << "XPXAXCXK static unpacker (c) by Sebastian Eschweiler" << endl;

	if (argc != 2)
	{
		printf("usage: %s [file to unpack]\n", argv[0]);
		exit(1);
	}

	cout << "unpacking file " << argv[1] << endl;

	try
	{
		basic_ifstream<unsigned char> t(argv[1], ios::binary);
		ustring s((istreambuf_iterator<unsigned char>(t)), istreambuf_iterator<unsigned char>());

		if (!XPackUnpacker::isPackedByXpack(s))
		{
			cout << "Error: file seems not to be packed by XPACK" << endl;
			exit(1);
		}

		ustring unpackedData = XPackUnpacker::unpack(s);

		string outputFileName(argv[1]);
		outputFileName.append(".unpacked");

		basic_ofstream<unsigned char> outFile(outputFileName, ios::binary);
		outFile << unpackedData;
	}
	catch (exception& e)
	{
		cout << "Error: " << e.what() << endl;
	}


	cout << "Done. Have a nice day :-)" << endl;

}