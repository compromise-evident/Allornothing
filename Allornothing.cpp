/// Allornothing - decrypt a file if all key carriers are present.
/// Nikolay Valentinovich Repnitskiy - License: WTFPLv2+ (wtfpl.net)


/* Version 2.1, plausibility ratio = 1:256, plausible messages per cipherfile =
value with 240,823,997 digits. Based on the One-time pad, data remains perfectly
secret even with all but one key. 1+GB RAM to encrypt. Get 5 100MB-keys per file
(500MB in 15m.)  Max file size: 100MB. Reserved randomness within every key file
is appended to all plainfiles to get 100,000,009 bytes then both that randomness
and plainfile are encrypted. This prevents key fragment exposure and identifying
analytics based on size. All keys are 100,000,009 bytes.  The first nine contain
encrypted file size for exact reversal. Proof: github.com/compromise-evident/OTP
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
How to run the program  -  Software package repositories for GNU+Linux operating
systems have all the tools you can imagine. Open a terminal and use this command
as root to install Geany and g++ on your computer: apt install geany g++   Geany
is a fast & lightweight text editor and Integrated Development Environment where
you can write and run code. g++ is the GNU compiler for C++ which allows written
code to run. The compiler operates in the background and displays errors in your
code as you will see in the lower Geany box. Make a new folder somewhere on your
machine. Paste this code into Geany. For clarity in auditing, enable indentation
guides: go to View >> Show Indentation Guides. Save the document as anything.cpp
within the newly-created folder. Use these shortcuts to run the program: F9, F5.
You may paste over this code with other  .cpp files, or open a new tab & repeat.
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
How to make an executable with g++  -  Save this program as anything.cpp, open a
terminal, and type g++ then space. Drag & drop this saved file into the terminal
and its directory will be  appended to your pending entry. Click on the terminal
and press enter.   a.out now resides in the user directory, you may rename it to
anything.  To run that executable, simply drag and drop it into a terminal, then
click on the terminal and press enter.  Reminder:  executable's effect-directory
is the user directory on your machine, for example:  /home/nikolay    Enjoy. */

#include <fstream>
#include <iostream>
using namespace std;

int main()
{	//                                                                                                                     |
	bool sector_accident_detection = true; // DEFAULT=TRUE ELSE NO FILE INTEGRITY TESTS.            ~Fatal if broken >     |
	     //Program writes to disk, reads it back, and compares it to RAM. Fails on mismatch.                               |
	
	cout << "\n(All or nothing)\n\n"
	
	     << "(1) Encrypt  -  Generate keys for a new file, these keys alone can re-create it.\n"
	     << "                Place your file in this directory and rename it to  \"plainfile\"\n"
	     << "                without any extensions (must be 1 to 100,000,000 bytes in size.)\n"
	     << "(2) Decrypt  -  Generate original file. Place all five keys in this directory.\n\n"
	
	     << "Requests overwrite permission\n"
	     << "when finished. Enter option: ";
	
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
		
		//Gets seeds for RNG.
		cout << "\nEnter a random nine-digit integer, repeat 90 times. (Get 500MB of keys in 15m.)\n\n";
		unsigned int user_seeds[90] = {0};
		for(int a = 0; a < 90; a++)
		{	if(a < 9) {cout << " " << (a + 1) << " of 90: ";} //Prints blank to align input status report (aesthetics.)
			else      {cout <<        (a + 1) << " of 90: ";}
			
			//Gets and checks input.
			cin >> user_seeds[a];
			if((user_seeds[a] > 999999999) || (user_seeds[a] < 100000000)) {cout << "\nOut of bounds, try again.\n"; return 0;}
		}
		
		cout << "\nWait 15 minutes...\n";
		
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
		
		//Gets file items and overwrites table_private[], leaving appended randomness if any.
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
		
		//Tests file integrity. This entire if-statement can be removed.
		if(sector_accident_detection == true)
		{	file_numbering = 1; //Resetting.
			file_name_key[4] = '1';
			char temp_file_byte;
			table_private_read_bookmark = 0;
			for(int a = 0; a < 5; a++)
			{	in_stream.open(file_name_key);
				for(int b = 0; b < 100000009; b++)
				{	in_stream.get(temp_file_byte);
					temp_integer_arithmetic = temp_file_byte;
					if(temp_integer_arithmetic < 0) {temp_integer_arithmetic += 256;}
					
					if(temp_integer_arithmetic != table_private[table_private_read_bookmark])
					{	in_stream.close();
						remove("key_1"); remove("key_2"); remove("key_3"); remove("key_4"); remove("key_5");
				
						cout << "\n\n\nBad sectors! There's something wrong with your storage device.\n\n"
						
						     << "For a quick fix, fill your storage device with a few gigabytes worth of any\n"
						     << "data then try this again. And do not disturb that dummy data as its purpose\n"
						     << "is to consume bad sectors and abused parts of the storage device.\n\n";
						
						return 0;
					}
					
					table_private_read_bookmark++;
				}
				in_stream.close();
				
				file_numbering++;
				file_name_key[4] = (file_numbering + 48);
			}
		}
		
		//Overwrites RAM of user_seeds[].
		for(int a = 0; a < 90; a++)
		{	user_seeds[a] = 123456789;
			user_seeds[a] = 987604321;
			user_seeds[a] = 0;
		}
		
		//Overwrites RAM of array: static unsigned char table_private[501000000].
		for(int a = 0; a < 501000000; a++) {table_private[a] = 0; table_private[a] = 255;}
		
		cout << "\n\nFinished! Five keys now reside in this directory.\n"
		     << "plainfile can be destroyed, and keys--distributed.\n\n"
		     
		     << "Now is your chance to copy the keys to external devices\n"
		     << "so that the keys here and original file can be heavily\n"
		     << "overwritten then removed. Continue? y/n: ";
		
		//Overwrites and removes all files on user's request (keys first because their size is known.)
		char wait; cin >> wait;
		if(wait == 'y')
		{	file_numbering = 1;
			file_name_key[4] = '1';
			for(int a = 0; a < 5; a++)
			{	out_stream.open(file_name_key); for(int a = 0; a < 100000009; a++) {out_stream << '\0';} out_stream.close(); //Binary: 00000000
				out_stream.open(file_name_key); for(int a = 0; a < 100000009; a++) {out_stream.put(-1);} out_stream.close(); //Binary: 11111111
				
				file_numbering++;
				file_name_key[4] = (file_numbering + 48);
			}
			
			out_stream.open("plainfile"); for(int a = 0; a < 100000000; a++) {out_stream << '\0';} out_stream.close(); //Binary: 00000000
			out_stream.open("plainfile"); for(int a = 0; a < 100000000; a++) {out_stream.put(-1);} out_stream.close(); //Binary: 11111111
			
			remove("plainfile"); remove("key_1"); remove("key_2"); remove("key_3"); remove("key_4"); remove("key_5"); //Bunching prevents external writes.
			
			cout << "\nOverwrite finished.\n";
		}
		else {cout << "\nFiles unharmed.\n";}
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
		
		cout << "\nWait 20 seconds...\n";
		
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
		
		//Tests file integrity. This entire if-statement can be removed.
		if(sector_accident_detection == true)
		{	char temp_file_byte;
			bool sector_accident = false;
			in_stream.open("plainfile");
			for(int a = 9; a < extracted_plainfile_size + 9; a++)
			{	in_stream.get(temp_file_byte);
				temp_integer_arithmetic = temp_file_byte;
				if(temp_integer_arithmetic < 0) {temp_integer_arithmetic += 256;}
				
				if(temp_integer_arithmetic != key[a]) {sector_accident = true; break;}
			}
			in_stream.close();
			
			if(sector_accident == true)
			{	//Overwrites RAM of array: static unsigned char key[100000009].
				for(int a = 0; a < 100000009; a++) {key[a] = 0; key[a] = 255;}
				
				cout << "\n\n\nBad sectors! There's something wrong with your storage device.\n\n"
				
				     << "For a quick fix, fill your storage device with a few gigabytes worth of any\n"
				     << "data then try this again. And do not disturb that dummy data as its purpose\n"
				     << "is to consume bad sectors and abused parts of the storage device.\n"
				     << "Overwrite keys and plainfile? y/n: ";
				
				//Overwrites and removes all files on user's request (keys first because their size is known.)
				char wait; cin >> wait;
				if(wait == 'y')
				{	file_numbering = 1;
					file_name_key[4] = '1';
					for(int a = 0; a < 5; a++)
					{	out_stream.open(file_name_key); for(int a = 0; a < 100000009; a++) {out_stream << '\0';} out_stream.close(); //Binary: 00000000
						out_stream.open(file_name_key); for(int a = 0; a < 100000009; a++) {out_stream.put(-1);} out_stream.close(); //Binary: 11111111
						
						file_numbering++;
						file_name_key[4] = (file_numbering + 48);
					}
					
					out_stream.open("plainfile"); for(int a = 0; a < 100000000; a++) {out_stream << '\0';} out_stream.close(); //Binary: 00000000
					out_stream.open("plainfile"); for(int a = 0; a < 100000000; a++) {out_stream.put(-1);} out_stream.close(); //Binary: 11111111
					
					remove("plainfile"); remove("key_1"); remove("key_2"); remove("key_3"); remove("key_4"); remove("key_5"); //Bunching prevents external writes.
					
					cout << "\nOverwrite finished.\n";
				}
				else {cout << "\nFiles unharmed.\n";}
				
				return 0;
			}
		}
		
		//Overwrites RAM of array: static unsigned char key[100000009].
		for(int a = 0; a < 100000009; a++) {key[a] = 0; key[a] = 255;}
		
		cout << "\n\nFinished! plainfile now resides in this directory.\n\n"
		
		     << "Now is your chance to observe or copy the plainfile\n"
		     << "onto external devices so that the keys here and original\n"
		     << "file can be heavily overwritten then removed. Continue? y/n: ";
		
		//Overwrites and removes all files on user's request (keys first because their size is known.)
		char wait; cin >> wait;
		if(wait == 'y')
		{	file_numbering = 1;
			file_name_key[4] = '1';
			for(int a = 0; a < 5; a++)
			{	out_stream.open(file_name_key); for(int a = 0; a < 100000009; a++) {out_stream << '\0';} out_stream.close(); //Binary: 00000000
				out_stream.open(file_name_key); for(int a = 0; a < 100000009; a++) {out_stream.put(-1);} out_stream.close(); //Binary: 11111111
				
				file_numbering++;
				file_name_key[4] = (file_numbering + 48);
			}
			
			out_stream.open("plainfile"); for(int a = 0; a < 100000000; a++) {out_stream << '\0';} out_stream.close(); //Binary: 00000000
			out_stream.open("plainfile"); for(int a = 0; a < 100000000; a++) {out_stream.put(-1);} out_stream.close(); //Binary: 11111111
			
			remove("plainfile"); remove("key_1"); remove("key_2"); remove("key_3"); remove("key_4"); remove("key_5"); //Bunching prevents external writes.
			
			cout << "\nOverwrite finished.\n";
		}
		else {cout << "\nFiles unharmed.\n";}
	}
}
