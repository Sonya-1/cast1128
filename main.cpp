#include"Cast128.h"
#include"CipherOFB.h"
#include"BMP.h"
#include<iostream>
#include<cstdint>
#include<map>
#include<vector>
#include<bitset>
#include<string>
#include<cmath>
#include<fstream>
using namespace std;


void encryptFileCastOFB(const char* inputFileName, const char* outFileName, Cast128::Key *key) {
	BMP img(inputFileName);	
	Cast128::Block iv;
	iv.Msg[0] = 0;
	iv.Msg[1] = 0;
	CipherOFB *cipher = new CipherOFB(iv, key);

	auto d = &img.data;

	for (size_t i = 0; i < img.data.size(); i += blockLength / 8) {
		(*cipher).crypt(d, i);
	}
	img.write(outFileName);
}

int distribution0(const char* filename) {
	BMP img(filename);
	bool b = 0;
	int d0 = 0;
	for (int i = 0; i < img.data.size(); i++) {
		for (int n = 0; n < 8; n++) {
			b = (bool((1 << n) & img.data[i]));
			if ((int)b == 0) {
				d0++;
			}
		}
	}
	return d0;
}

int distribution1(const char* filename) {
	BMP img(filename);
	bool b = 0;
	int d1 = 0;
	for (int i = 0; i < img.data.size(); i++) {
		for (int n = 0; n < 8; n++) {
			b = (bool((1 << n) & img.data[i]));
			if ((int)b == 1) {
				d1++;
			}
		}
	}
	return d1;
}

double correlation(const char* src, const char* encr) {
	BMP img1(src);
	BMP img2(encr);

	double averageX = 0;
	bool b;
	for (int i = 0; i < img1.data.size(); i++) {
		for (int n = 0; n < 8; n++) {
			b = (bool((1 << n) & img1.data[i]));
			if ((int)b == 1) {
				averageX++;
			}
		}
	}
	averageX /= img1.data.size() * 8;

	double averageY = 0;
	for (int i = 0; i < img2.data.size(); i++) {
		for (int n = 0; n < 8; n++) {
			b = (bool((1 << n) & img2.data[i]));
			if ((int)b == 1) {
				averageY++;
			}
		}
	}
	averageY /= img2.data.size() * 8;

 	double correlationTop = 0.0;
	double correlationBottom = 0.0;
	for (int i = 0; i < img1.data.size(); ++i) {
		for (int j = 0; j < 8; ++j) {
			std::bitset<8> bitX(img1.data[i]);
			std::bitset<8> bitY(img2.data[i]);
			bool x = bitX[j];
			bool y = bitY[j];
			correlationTop += ((x - averageX) * (y - averageY));
			correlationBottom += sqrt(pow(x - averageX, 2) * pow(y - averageY, 2));
		}
	}
	return abs(correlationTop / correlationBottom);
}

double frequencyTest(Cast128::Block b) {
	bool a = 0;
	int d0 = 0;
	int d1 = 0;
	std::vector<uint8_t> mask;
	mask.push_back((uint8_t)b.Msg[0]);
	mask.push_back(b.Msg[0] >> 8);
	mask.push_back(b.Msg[0] >> 16);
	mask.push_back(b.Msg[0] >> 24);
	mask.push_back(b.Msg[1]);
	mask.push_back(b.Msg[1] >> 8);
	mask.push_back(b.Msg[1] >> 16);
	mask.push_back(b.Msg[1] >> 24);
	for (int i = 0; i < 8; i++) {
		for (int n = 0; n < 8; n++) {
			a = (bool((1 << n) & mask[i]));
			if ((int)a == 0) {
				d0++;
			}
			if ((int)a == 1) {
				d1++;
			}
		}
	}
	double x = pow((d0 - d1), 2) / blockLength;
	return x;
}

double seriesTest(Cast128::Block b) {
	string bits;
	bool a;
	std::vector<uint8_t> mask;
	mask.push_back((uint8_t)b.Msg[0]);
	mask.push_back(b.Msg[0] >> 8);
	mask.push_back(b.Msg[0] >> 16);
	mask.push_back(b.Msg[0] >> 24);
	mask.push_back(b.Msg[1]);
	mask.push_back(b.Msg[1] >> 8);
	mask.push_back(b.Msg[1] >> 16);
	mask.push_back(b.Msg[1] >> 24);
	for (int i = 0; i < 8; i++) {
		for (int n = 0; n < 8; n++) {
			a = ((1 << n) & mask[i]);
			bits.push_back((char)((int)a + 48));
		}
	}
	int len1f0 = 0, len2f0 = 0, len3f0 = 0, len4f0 = 0;
	int len1f1 = 0, len2f1 = 0, len3f1 = 0, len4f1 = 0;

	for (int i = 0; i < bits.length(); i++) {
		int j = i;
		if (i < (bits.length() - 5) && i != 0 && bits.at(j) == '1' && bits.at(j + 1) == '1' 
			&& bits.at(j + 2) == '1' && bits.at(j + 3) == '1' && bits.at(j - 1) == '0' && bits.at(j + 4) == '0') {
			len4f1++;
			continue;
		}
		if (i < (bits.length() - 4) && i != 0 && bits.at(j) == '1' && bits.at(j + 1) == '1'
			&& bits.at(j + 2) == '1' && bits.at(j - 1) == '0' && bits.at(j + 3) == '0') {
			len3f1++;
			continue;
		}
		if (i < (bits.length() - 3) && i != 0 && bits.at(j) == '1' && bits.at(j + 1) == '1'
			&& bits.at(j - 1) == '0' && bits.at(j + 2) == '0') {
			len2f1++;
			continue;
		}
		if (i < (bits.length() - 1) && i != 0 && bits.at(j) == '1'
			&& bits.at(j - 1) == '0' && bits.at(j + 1) == '0') {
			len1f1++;
			continue;
		}
		if (i < (bits.length() - 5) && i != 0 && bits.at(j) == '0' && bits.at(j + 1) == '0'
			&& bits.at(j + 2) == '0' && bits.at(j + 3) == '0' && bits.at(j - 1) == '1' && bits.at(j + 4) == '1') {
			len4f0++;
			continue;
		}
		if (i < (bits.length() - 4) && i != 0 && bits.at(j) == '0' && bits.at(j + 1) == '0'
			&& bits.at(j + 2) == '0' && bits.at(j - 1) == '1' && bits.at(j + 3) == '1') {
			len3f0++;
			continue;
		}
		if (i < (bits.length() - 3) && i != 0 && bits.at(j) == '0' && bits.at(j + 1) == '0'
			&& bits.at(j - 1) == '1' && bits.at(j + 2) == '1') {
			len2f0++;
			continue;
		}
		if (i < (bits.length() - 1) && i != 0 && bits.at(j) == '0'
			&& bits.at(j - 1) == '1' && bits.at(j + 1) == '1') {
			len1f0++;
			continue;
		}
	}
	
	double e4 = (bits.length() - 4 + 3) / pow(2, (4 + 2));
	double e3 = (bits.length() - 3 + 3) / pow(2, (3 + 2));
	double e2 = (bits.length() - 2 + 3) / pow(2, (2 + 2));
	double e1 = (bits.length() - 1 + 3) / pow(2, (1 + 2));

	double x4f0 = pow((len4f0 - e4), 2) / e4;
	double x3f0 = pow((len3f0 - e3), 2) / e3;
	double x2f0 = pow((len2f0 - e2), 2) / e2;
	double x1f0 = pow((len1f0 - e1), 2) / e1;
	double sumf0 = x4f0 + x3f0 + x2f0 + x1f0;

	double x4f1 = pow((len4f1 - e4), 2) / e4;
	double x3f1 = pow((len3f1 - e3), 2) / e3;
	double x2f1 = pow((len2f1 - e2), 2) / e2;
	double x1f1 = pow((len1f1 - e1), 2) / e1;
	double sumf1 = x4f1 + x3f1 + x2f1 + x1f1;

	return sumf0 + sumf1;
}

double autocorrelationTest(Cast128::Block b, int d) {
	vector<int> bits;
	bool a;
	std::vector<uint8_t> mask;
	mask.push_back((uint8_t)b.Msg[0]);
	mask.push_back(b.Msg[0] >> 8);
	mask.push_back(b.Msg[0] >> 16);
	mask.push_back(b.Msg[0] >> 24);
	mask.push_back(b.Msg[1]);
	mask.push_back(b.Msg[1] >> 8);
	mask.push_back(b.Msg[1] >> 16);
	mask.push_back(b.Msg[1] >> 24);
	for (int i = 0; i < 8; i++) {
		for (int n = 0; n < 8; n++) {
			a = ((1 << n) & mask[i]);
			bits.push_back((int)a);
		}
	}
	int A = 0;
	for (int i = 0; i < bits.size() - d - 1; i++) {
		A += bits[i] ^ bits[i + d];
	}
	
	double x = (2 * (A - (bits.size() - d) / 2)) / sqrt(bits.size() - d);

	return x;
}

void printBits(Cast128::Block b) {
	bool a;
	std::vector<uint8_t> mask;
	mask.push_back((uint8_t)b.Msg[0]);
	mask.push_back(b.Msg[0] >> 8);
	mask.push_back(b.Msg[0] >> 16);
	mask.push_back(b.Msg[0] >> 24);
	mask.push_back(b.Msg[1]);
	mask.push_back(b.Msg[1] >> 8);
	mask.push_back(b.Msg[1] >> 16);
	mask.push_back(b.Msg[1] >> 24);

	for (int i = 0; i < 8; i++) {
		for (int n = 0; n < 8; n++) {
			a = ((1 << n) & mask[i]);
			cout << a << "\t";
		}
		cout << endl;
	}
}

int main(int argc, char* argv[]) {
	Cast128::Key key;
	Cast128::readKey("12345678vbabcd12", &key);

	vector<Cast128::Block> vectorBlocks;

	vectorBlocks = Cast128::readFile("c:/tmp/img.bmp");
	Cast128::Block b = Cast128::invertSecond(vectorBlocks[0]);

	Cast128::Block bCh = Cast128::go(key, b, true);

	Cast128::Block b1 = Cast128::invertThird(vectorBlocks[0]);
	Cast128::Block b1Ch = Cast128::go(key, b1, true);

	double x = frequencyTest(bCh);
	double x1 = frequencyTest(b1Ch);
	cout << "Frequency test\nInvert second bit in block: " << x << "\nInvert third bit in block: " << x1 << endl;

	double u = seriesTest(bCh);
	double u1 = seriesTest(b1Ch);
	cout << "\nSeries test\nInvert second bit in block: " << u << "\nInvert third bit in block: " << u1 << endl;

	int d = 21;
	double y = autocorrelationTest(bCh, d);
	double y1 = autocorrelationTest(b1Ch, d);
	cout << "\nAutocorrelation test\nInvert second bit in block: " << y << "\nInvert third bit in block: " << y1 << endl;

	ofstream file("c:/tmp/autotest.txt");
	for (int i = 1; i < 60; i++) {
		file << i << autocorrelationTest(bCh, i) << endl;
	}
	/*
	Cast128::encryptFile("c:/tmp/img.bmp", "c:/tmp/img1.bmp", key);
	Cast128::decryptFile("c:/tmp/img1.bmp", "c:/tmp/img2.bmp", key);
	Cast128::decryptFile("c:/tmp/img1_ch.bmp", "c:/tmp/img2_ch.bmp", key);

	encryptFileCastOFB("c:/tmp/img.bmp", "c:/tmp/img_ofb.bmp", &key);
	encryptFileCastOFB("c:/tmp/img_ofb.bmp", "c:/tmp/img_ofb_dec.bmp", &key);
	encryptFileCastOFB("c:/tmp/img_ofb_ch.bmp", "c:/tmp/img_ofb_dec_ch.bmp", &key);

	int d0 = distribution0("c:/tmp/img1.bmp");
	int d1 = distribution1("c:/tmp/img1.bmp");
	cout << "CAST-128" << endl;
	cout << "d0 = " << d0 << "\nd1 = " << d1 << endl;
	double c = correlation("c:/tmp/img.bmp", "c:/tmp/img1.bmp");
	cout << "correlation = " << c << endl;

	cout << "\nCAST-128 OFB" << endl;
	int d0_ofb = distribution0("c:/tmp/img_ofb.bmp");
	int d1_ofb = distribution1("c:/tmp/img_ofb.bmp");
	cout << "d0 = " << d0_ofb << "\nd1 = " << d1_ofb << endl;
	double c1 = correlation("c:/tmp/img.bmp", "c:/tmp/img_ofb.bmp");
	cout << "correlation = " << c1 << endl;
	*/
	return 0;
}