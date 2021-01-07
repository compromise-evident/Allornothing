/// Allornothing - decrypt a file if all key carriers are present
/// Version 1, plausibility ratio = 1:256, number of plausible messages per cipherfile contains 240,823,997 decimal digits.
/// Based on the One-time pad, data remains perfectly secret even with all but one key.
/// Nikolay Valentinovich Repnitskiy - License: WTFPLv2+ (wtfpl.net.)

/* Requires 1+GB RAM to encrypt. 5 100MB-keys per file, 100MB max file size. Get 500MB of keys in 25m @2.1GHz.
As with all my OTPs, reserved randomness within the key files is appended to all plainfiles to get 100,000,009 bytes total
then both that randomness and plainfile are encrypted.  This prevents key fragment exposure and identifying file analytics
based on their size. All cipherfiles are 100,000,009 bytes. The first 9 contain encrypted file size-for exact reproduction.
Encryption: plainfile[a] = key_1[a] + key_2[a] + ... + key_5[a] mod 256  where key_1[a] is adjusted after sum(keys 2 to 5).
Proof: https://github.com/compromise-evident/OTP/blob/main/Perfect%20secrecy%20and%20computational%20difficulty%20proof.pdf
--------------------------------------------------------------------------------------------------------------------------
How to run the program - Software package repositories for GNU+Linux operating systems have all the developer tools needed.
Open a terminal and use the following command as root to install  Geany  and  g++  on your computer:  apt install geany g++
Geany is a fast & lightweight text editor and Integrated Development Environment (IDE) in which you can write and run code.
g++ is the GNU compiler for C++ which allows written code to run. The compiler operates in the background automatically and
displays errors in your code as you will see in the lower Geany box.  Create a folder somewhere on your machine. Open Geany
and paste this code into the blank Geany page.  (A good tip for clarity in auditing is to enable indentation guides for the
block braces. Go to View > Show Indentation Guides.) Save the file as anything.cpp within the newly-created folder. Now you
can use these shortcuts to run the program: F9, F5. Whenever you wish to run the program again, open Geany and use the same
shortcuts. This will work for any single C++ file whether you paste over the current code or open a new tab and repeat. */

#include <cstdlib>  //For rand() & srand() (here: user-defined seeds only.)
#include <fstream>  //For file I/O (creates, writes to, and/or reads from 1 input file and 5 key files.)
#include <iostream>
using namespace std;

int main()
{	cout << "\n(All or nothing)\n\n"
	
	     << "(1) Encrypt  -  Generate keys for a new file, these keys alone can re-create it.\n"
	     << "                Place your file in this directory and rename it to  \"plainfile\"\n"
	     << "                without any extensions (must be 1 to 100,000,000 bytes in size.)\n"
	     << "(2) Decrypt  -  Generate original file. Place all five keys in this directory.\n\n"
	
	     << "Enter option: ";
	
	int user_option; cin >> user_option;
	if((user_option != 1) && (user_option != 2)) {cout << "\nInvalid, program ended.\n"; return 0;}
	//(You can run each if() holding options 1 and 2 in isolation--they are self-sustained.)
	
	
	
	
	
	//______________________________________________________Encrypt___________________________________________________//
	if(user_option == 1)
	{	ifstream in_stream;
		ofstream out_stream;
		
		//Checks if plainfile is present.
		char sniffed_one_file_character;
		in_stream.open("plainfile");
		if(in_stream.fail() == true) {in_stream.close(); cout << "\n\nplainfile misnamed or not present.\n"; return 0;}
		in_stream.get(sniffed_one_file_character);
		if(in_stream.eof() == true)  {in_stream.close(); cout << "\n\nplainfile cannot be empty.\n";         return 0;}
		in_stream.close();
		
		//Fills user_seeds[].
		cout << "\nEnter a random nine-digit integer, repeat 90 times. (Get 500MB of keys in 25m.)\n\n";
		unsigned int user_seeds[90] = {0};
		for(int a = 0; a < 90; a++)
		{	if(a < 9) {cout << " " << (a + 1) << " of 90: ";} //Prints blank to align input status report (aesthetics.)
			else      {cout <<        (a + 1) << " of 90: ";}
			
			cin >> user_seeds[a];
		}
		
		//Fills table_private[] with randomness 0 - 255 (later converted to (-128 - 127) upon writing to files.)
		static unsigned char table_private[501000000] = {0};
		int temp_integer_arithmetic;
		for(int a = 0; a < 90; a++) //Constructively applies random digits to table_private[] based on the 90 seeds provided by the user.
		{	srand(user_seeds[a]);   //WRITES ALTERNATING BETWEEN LEFT TO RIGHT & RIGHT TO LEFT. Alternation is based on the 90 user seeds.
			
			if((user_seeds[a] % 2) == 0)
			{	for(int b = 0; b < 501000000; b++) //WRITES LEFT TO RIGHT.
				{	temp_integer_arithmetic = table_private[b];
					temp_integer_arithmetic += (rand() % 256);
					table_private[b] = (temp_integer_arithmetic % 256);
				}
			}
			else
			{	for(int b = 500999999; b >= 0; b--) //WRITES RIGHT TO LEFT.
				{	temp_integer_arithmetic = table_private[b];
					temp_integer_arithmetic += (rand() % 256);
					table_private[b] = (temp_integer_arithmetic % 256);
				}
			}
		}
		
		//Adding additional randomness in table_private[].
		unsigned int seeds_sum = 0;
		for(int a = 0; a < 90; a++) {seeds_sum = ((seeds_sum + user_seeds[a]) % 1000000000);}
		srand(seeds_sum); //A new 9-digit seed comes from the sum of ALL user-seeds.
		for(int a = 0; a < 501000000; a++) //WRITES LEFT TO RIGHT.
		{	temp_integer_arithmetic = table_private[a];
			temp_integer_arithmetic += (rand() % 256);
			table_private[a] = (temp_integer_arithmetic % 256);
		}
		
		//Again, adding additional randomness in table_private[].
		seeds_sum = 0;
		for(int a = 0; a < 90; a += 2) {seeds_sum = ((seeds_sum + user_seeds[a]) % 1000000000);}
		srand(seeds_sum); //Another new 9-digit seed comes from the sum of EVERY OTHER user-seed.
		for(int a = 500999999; a >= 0; a--) //WRITES RIGHT TO LEFT.
		{	temp_integer_arithmetic = table_private[a];
			temp_integer_arithmetic += (rand() % 256);
			table_private[a] = (temp_integer_arithmetic % 256);
		}
		
		//Gets file items and overwrites plainfile[], leaving appended randomness if any.
		char temp_file_byte;
		int file_size_counter = 0;
		in_stream.open("plainfile");
		in_stream.get(temp_file_byte);
		for(int a = 9; in_stream.eof() == false; a++)
		{	file_size_counter++;
			if(file_size_counter > 100000000)
			{	file_size_counter--;
				in_stream.close();
				cout << "\n\nplainfile too large! Encrypting the first 100,000,000 bytes...\n";
				break;
			}
			
			if(temp_file_byte < 0)
			{	temp_integer_arithmetic = temp_file_byte;
				table_private[a] = (temp_integer_arithmetic + 256);
			}
			else {table_private[a] =  temp_file_byte;}
			
			in_stream.get(temp_file_byte);
		}
		in_stream.close();
		
		//Writes the file size to the first 9 table_private[] elements. This will be encrypted.
		file_size_counter += 1000000000;
		for(int a = 8; a >= 0; a--)
		{	table_private[a] = (file_size_counter % 10);
			file_size_counter /= 10;
		}
		
		///Encrypts size info, plainfile, and appended randomness if any--using the other 400,000,036 in table_private[].
		//table_private can be thought of as being five 100MB-keys strung together. This operation turns the first
		//100,000,009 items in table_private[] back into a key but this time, adjusted so as to equal the values of
		//the plainfile if summing all key elements % 256. key_1[n] = x where sum(keys 2 to 5) + x = plainfile[n].
		int key_sum;
		int temp_x = 0;
		for(int a = 0; a < 100000009; a++)
		{	key_sum  = table_private[a + 100000009];
			key_sum += table_private[a + 200000018];
			key_sum += table_private[a + 300000027];
			key_sum += table_private[a + 400000036];
			key_sum %= 256;
			
			for(int b = 0; b < 256; b++)
			{	if(((key_sum + temp_x) % 256) == table_private[a])
				{	table_private[a] = temp_x;
					break;
				}
				temp_x++;
			}
			
			temp_x = 0;
		}
		
		//Creates and writes to all five key files.
		char file_name_key[6] = {"key_1"};
		int file_numbering = 1;
		int table_private_read_bookmark = 0;
		for(int a = 0; a < 5; a++)
		{	out_stream.open(file_name_key);
			for(int b = 0; b < 100000009; b++)
			{	if(table_private[a] < 128) {out_stream.put(table_private[table_private_read_bookmark]      );}
				else                       {out_stream.put(table_private[table_private_read_bookmark] - 256);}
				
				table_private_read_bookmark++;
			}
			out_stream.close();
			
			file_numbering++;
			file_name_key[4] = (file_numbering + 48);
		}
		
		//Overwrites RAM of user_seeds[].
		for(int a = 0; a < 90; a++)
		{	user_seeds[a] = 123456789;
			user_seeds[a] = 987604321;
			user_seeds[a] = 0;
		}
		
		//Overwrites RAM of array table_private[].
		for(int a = 0; a < 501000000; a++)
		{	for(int b = 0; b < 10; b++) {table_private[a] = b;}
		}
		
		cout << "\n\nFinished! Five keys now reside in this directory.\n"
		     << "plainfile can be destroyed, and keys--distributed.\n";
	}
	
	
	
	
	
	//______________________________________________________Decrypt___________________________________________________//
	if(user_option == 2)
	{	ifstream in_stream;
		ofstream out_stream;
		
		//Checks if all keys are present.
		char file_name_key[6] = {"key_1"};
		int file_numbering = 1;
		for(int a = 0; a < 5; a++)
		{	in_stream.open(file_name_key);
			if(in_stream.fail() == true)
			{	in_stream.close();
				cout << "\n\nNeed five keys! (key_1  key_2  key_3  key_4  key_5)\n";
				return 0;
			}
			in_stream.close();
			
			file_numbering++;
			file_name_key[4] = (file_numbering + 48);
		}
		
		///Gets key files and decrypts dynamically.
		file_numbering = 1; //Resetting.
		file_name_key[4] = '1';
		static unsigned char key[100000009] = {0};
		char temp_file_byte;
		int temp_integer_arithmetic;
		for(int a = 0; a < 5; a++)
		{	in_stream.open(file_name_key);
			for(int b = 0; b < 100000009; b++)
			{	in_stream.get(temp_file_byte);
				temp_integer_arithmetic = temp_file_byte;
				if(temp_integer_arithmetic < 0) {temp_integer_arithmetic += 256;}
				
				temp_integer_arithmetic += key[b];
				key[b] = (temp_integer_arithmetic % 256);
			}
			in_stream.close();
			
			file_numbering++;
			file_name_key[4] = (file_numbering + 48);
		}
		
		//Extracts plainfile size information.
		int extracted_plainfile_size = 0;
		int digits_place_multiplier = 100000000;
		for(int a = 0; a < 9; a++)
		{	if(key[a] > 0) {extracted_plainfile_size += (key[a] * digits_place_multiplier);}
			digits_place_multiplier /= 10;
		}
		
		//Creates the plainfile.
		out_stream.open("plainfile");
		for(int a = 9; a < extracted_plainfile_size + 9; a++)
		{	if(key[a] < 128) {out_stream.put(key[a]      );}
			else             {out_stream.put(key[a] - 256);}
		}
		out_stream.close();
		
		//Overwrites RAM of array key[].
		for(int a = 0; a < 100000009; a++)
		{	for(int b = 0; b < 10; b++) {key[a] = b;}
		}
		
		cout << "\n\nFinished! plainfile now resides in this directory.\n";
	}
}
