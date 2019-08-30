#include<bits/stdc++.h>
using namespace std;
#define MAX_CHOSEN_PAIRS 10000

//32-bit sub-keys, 6 in all required for encryption in FEAL-4
unsigned long subkey[6];

//cyclically rotates the bits by two positions to the left
unsigned char rotl2(unsigned char a) {return ((a << 2) | (a >> 6));}

//function that separates the left half of  the plain text
unsigned long leftHalf(unsigned long long a) {return (a >> 32LL);}

//function that separates the right half of the plain text
unsigned long rightHalf(unsigned long long a) {return a;}

//function to separate the bytes of text
unsigned char sepByte(unsigned long a, unsigned char index) {return a >> (8 * index);}

//function to combine bytes of the text
unsigned long combineBytes(unsigned char b3, unsigned char b2, unsigned char b1, unsigned char b0)
{
 		 return b3 << 24L | (b2 << 16L) | (b1 << 8L) | b0;
}

//function to combine the left and the right halves of the
//cipher text
unsigned long long combineHalves(unsigned long leftHalf, unsigned long rightHalf)
{
 		 return (((unsigned long long)(leftHalf)) << 32LL) | (((unsigned long long)(rightHalf)) & 0xFFFFFFFFLL);
}

//design of g-box
//Gx(a,b)=(a+b+x)%MOD <<<2
//<<< implies left cyclic rotation by two positions of the bits
//only two variants of g-box possible
//with x(mode here) taking value 0 & 1
unsigned char gBox(unsigned char a, unsigned char b, unsigned char mode)
{
    return rotl2(a + b + mode);
}

//design of f-box
unsigned long fBox(unsigned long plain)
{
    //separate the bytes of the plain text plainText=x3x2x1x0 into namely x0,x1,x2 and x3
    unsigned char x0 = sepByte(plain, 0);
    unsigned char x1 = sepByte(plain, 1);
    unsigned char x2 = sepByte(plain, 2);
    unsigned char x3 = sepByte(plain, 3);

    //t0 is one of the inputs to the g-box corresponding to the x1 input
    unsigned char t0 = (x2 ^ x3);

    //t1 is one of the inputs to the g-box corresponding to the x1 input
    unsigned char t1 = (x0 ^ x1);

    //3 representing the MSB and 0 representing the LSB
    //of the output of the f-box
    unsigned char y1 = gBox(t1, t0, 1);
    unsigned char y0 = gBox(x0, y1, 0);
    unsigned char y2 = gBox(t0, y1, 0);
    unsigned char y3 = gBox(x3, y2, 1);

    //combine the bytes of the output text y0,y1,y2,y3 and return as 32-bit y3y2y1y0
    return combineBytes(y3, y2, y1, y0);
}

//design implementation of FEAL-4
unsigned long long encrypt(unsigned long long plain)
{
    //initial left and right halves of the plain Text
    unsigned long left = leftHalf(plain);
    unsigned long right = rightHalf(plain);

    left = left ^ subkey[4];
    right = right ^ subkey[5];

    //Round 1
    unsigned long round2Left = left ^ right;
    unsigned long round2Right = left ^ fBox(round2Left ^ subkey[0]);

    //Round 2
    unsigned long round3Left = round2Right;
    unsigned long round3Right = round2Left ^ fBox(round2Right ^ subkey[1]);

    //Round 3
    unsigned long round4Left = round3Right;
    unsigned long round4Right = round3Left ^ fBox(round3Right ^ subkey[2]);

    //Round 4
    unsigned long cipherLeft = round4Left ^ fBox(round4Right ^ subkey[3]);
    unsigned long cipherRight = cipherLeft ^ round4Right;

    //combine both the halves
    return combineHalves(cipherLeft, cipherRight);
}

//generate the 32-bit sub-keys
void generateSubkeys(int seed)
{
    //seed for using seeding the rand() function
    srand(seed);

    //i corresponding to the i th indexed sub-key
    for(int i = 0; i <  6; i++)
    {
        subkey[i] = (rand() << 16L) | (rand() & 0xFFFFL);

        //bound the sub-key
        subkey[i]=subkey[i]%(unsigned long)10000;
    }

}

//number of plain text pairs
int numPlain;
unsigned long long plain0[MAX_CHOSEN_PAIRS];
unsigned long long cipher0[MAX_CHOSEN_PAIRS];
unsigned long long plain1[MAX_CHOSEN_PAIRS];
unsigned long long cipher1[MAX_CHOSEN_PAIRS];

//function to undo the last operation of XOR of the
//left and right half of the cipher text
void undoFinalOperation()
{
        for(int i = 0; i < numPlain; i++)
        {
            //separating and undoing the last operation of the cipherText0 series
            unsigned long cipherLeft0 = leftHalf(cipher0[i]);
            unsigned long cipherRight0 = rightHalf(cipher0[i]) ^ cipherLeft0;

            //separating and undoing the last operation of the cipherText1 series
            unsigned long cipherLeft1 = leftHalf(cipher1[i]);
            unsigned long cipherRight1 = rightHalf(cipher1[i]) ^ cipherLeft1;

            //reconstructing the cipherText0 series
			cipher0[i] = combineHalves(cipherLeft0, cipherRight0);

			//reconstructing the cipherText1 series
			cipher1[i] = combineHalves(cipherLeft1, cipherRight1);
         }
}

//function to crack last round
unsigned long crackLastRound(unsigned long outdiff)
{
    printf("  Using output differential of 0x%08x\n", outdiff);
    printf("  Cracking...");

    unsigned long fakeK;
    for(fakeK = 0x00000000L; fakeK < 0xFFFFFFFFL; fakeK++)
    {
        //count when the calculated differential matches the actual differential
        int score = 0;

        for(int c = 0; c < numPlain; c++)
        {
            //cout<<"c "<<c<<" key checked "<<fakeK<<endl;
            unsigned long cipherLeft = (cipher0[c] >> 32LL);
            cipherLeft ^= (cipher1[c] >> 32LL);
            unsigned long cipherRight = cipher0[c] & 0xFFFFFFFFLL;
            cipherRight ^= (cipher1[c] & 0xFFFFFFFFLL);

            unsigned long Y = cipherRight;
            unsigned long Z = cipherLeft ^ outdiff;

            unsigned long fakeRight = cipher0[c] & 0xFFFFFFFFLL;
            unsigned long fakeLeft = cipher0[c] >> 32LL;
            unsigned long fakeRight2 = cipher1[c] & 0xFFFFFFFFLL;
            unsigned long fakeLeft2 = cipher1[c] >> 32LL;

            unsigned long Y0 = fakeRight;
            unsigned long Y1 = fakeRight2;

            unsigned long fakeInput0 = Y0 ^ fakeK;
            unsigned long fakeInput1 = Y1 ^ fakeK;
            unsigned long fakeOut0 = fBox(fakeInput0);
            unsigned long fakeOut1 = fBox(fakeInput1);
            unsigned long fakeDiff = fakeOut0 ^ fakeOut1;

            if (fakeDiff == Z) score++; else break;
        }

        if (score == numPlain)
        {
            printf("found subkey : 0x%08lx\n", fakeK);
            return fakeK;
        }
    }

    cout<<"failed"<<endl;
    return 0;
}


//function to generate plain text pairs
//randomized generation to avoid false
void chosenPlaintext(unsigned long long diff)
{
 	cout<<"Generating "<<numPlain<<" chosen-plaintext pairs"<<endl;
	printf("Using input differential of 0x%016llx\n", diff);

    srand(time(NULL));

    for(int c = 0; c < numPlain; c++)
    {
        plain0[c] = (rand() & 0xFFFFLL) << 48LL;
        plain0[c] += (rand() & 0xFFFFLL) << 32LL;
        plain0[c] += (rand() & 0xFFFFLL) << 16LL;
        plain0[c] += (rand() & 0xFFFFLL);

        //encrypting the plain text
        cipher0[c] = encrypt(plain0[c]);

        //generating the other buddy of plain text using the input differential
        plain1[c] = plain0[c] ^ diff;

        //encrypting the plain text
        cipher1[c] = encrypt(plain1[c]);
    }
}

void undoLastRound(unsigned long crackedSubkey)
{
 	 for(int c = 0; c < numPlain; c++)
 	 {
            //getting the left and right halves of the cipher text
 	        unsigned long cipherLeft0 = leftHalf(cipher0[c]);
            unsigned long cipherRight0 = rightHalf(cipher0[c]);
            unsigned long cipherLeft1 = leftHalf(cipher1[c]);
            unsigned long cipherRight1 = rightHalf(cipher1[c]);

            //updating the left halves
			cipherLeft0 = cipherRight0;
			cipherLeft1 = cipherRight1;

			//updating the right halves
			cipherRight0 = fBox(cipherLeft0 ^ crackedSubkey) ^ (cipher0[c] >> 32LL);
			cipherRight1 = fBox(cipherLeft1 ^ crackedSubkey) ^ (cipher1[c] >> 32LL);

            //combining both the halves
			cipher0[c] = combineHalves(cipherLeft0, cipherRight0);
			cipher1[c] = combineHalves(cipherLeft1, cipherRight1);
   	 }
}



int main()
{

    cout<<"-------------------------------------------FEAL-4 DIFFERENTIAL CRYPTANALYSIS DEMO----------------------------------------"<<endl;
    cout<<endl;



    generateSubkeys(time(NULL));
	numPlain = 10000;

    //uncomment to see the generated sub-keys
    //for(int i=0;i<6;i++)
    //cout<<"0x"<<std::hex<<subkey[i]<<endl;



	//first input differential to be used for cracking round 4
	unsigned long long inputDifferential1 = 0x8080000080800000LL;

	//second input differential to be used for cracking round 3
	unsigned long long inputDifferential2 = 0x0000000080800000LL;

	//third input differential to be used for cracking round 2
	unsigned long long inputDifferential3 = 0x0000000002000000LL;

	//common output differential
	unsigned long outDiff = 0x02000000L;

    //initial start time
	unsigned long fullStartTime = time(NULL);

//Operations on Round 4
    cout<<"ROUND 4"<<endl;

    //generating the chosen plain texts for the given input differential
 	chosenPlaintext(inputDifferential1);

 	//undoing the last operation of XOR
 	undoFinalOperation();

 	//local start time
	unsigned long startTime = time(NULL);

	//the cracked sub-key for the round
	unsigned long crackedSubkey3 = crackLastRound(outDiff);

	//local end time
    unsigned long endTime = time(NULL);

   	cout<<"Time to crack round #4 ="<<endTime - startTime<<" seconds"<<endl;

   	cout<<endl<<endl;

//CRACKING ROUND 3
    printf("ROUND 3\n");

    //generating the chosen plain texts for the given input differential
 	chosenPlaintext(inputDifferential2);

 	//undoing the last operation of XOR
 	undoFinalOperation();

 	//undoing the last round using the sub-key cracked previously
 	undoLastRound(crackedSubkey3);

 	//local start time
	startTime = time(NULL);

	//sub-key cracked in this round
	unsigned long crackedSubkey2 = crackLastRound(outDiff);

	//local end time
    endTime = time(NULL);

   	cout<<"Time to crack round #3 ="<<endTime - startTime<<" seconds"<<endl;


   	cout<<endl<<endl;

//CRACKING ROUND 2
    printf("ROUND 2\n");

    //generating the chosen plain texts for the given input differential
 	chosenPlaintext(inputDifferential3);

 	//undoing the last operation of XOR
 	undoFinalOperation();

 	//undoing the last round using the sub-key cracked previously
 	undoLastRound(crackedSubkey3);

 	//undoing the last round using the sub-key cracked previously
 	undoLastRound(crackedSubkey2);

 	//local start time
	startTime = time(NULL);

	//sub-key cracked in this round
	unsigned long crackedSubkey1 = crackLastRound(outDiff);

	//local end time
    endTime = time(NULL);

    cout<<"Time to crack round #2 ="<<endTime - startTime<<" seconds"<<endl;


    cout<<endl<<endl;


//CRACK ROUND 1
    printf("ROUND 1\n");

    //since the last round cannot be cracked using differential
    //plain text is not generated for this round the previous generated
    //plain text is manipulated

    //undo the previous rounds using the sub-key cracked previously
    undoLastRound(crackedSubkey1);
	unsigned long crackedSubkey0 = 0;
	unsigned long crackedSubkey4 = 0;
	unsigned long crackedSubkey5 = 0;

	printf("  Cracking...");

	//local start time
	startTime = time(NULL);

	//guessing the local sub-key K0
    unsigned long guessK0;

    for(guessK0 = 0; guessK0 < 0xFFFFFFFFL; guessK0++)
    {
          //guessing the local sub-key K4
	      unsigned long guessK4 = 0;

	      //guessing the local sub-key K5
	      unsigned long guessK5 = 0;

 		  for(int c = 0; c < numPlain; c++)
 		  {
		   		unsigned long plainLeft0 = leftHalf(plain0[c]);
		   		unsigned long plainRight0 = rightHalf(plain0[c]);
		   		unsigned long cipherLeft0 = leftHalf(cipher0[c]);
		   		unsigned long cipherRight0 = rightHalf(cipher0[c]);

	 	   		unsigned long tempy0 = fBox(cipherRight0 ^ guessK0) ^ cipherLeft0;
	 	  		if (guessK4 == 0)
	 	  		{
				   guessK4 = tempy0 ^ plainLeft0;
  		           guessK5 = tempy0 ^ cipherRight0 ^ plainRight0;
			    }
			  	else if (((tempy0 ^ plainLeft0) != guessK4) || ((tempy0 ^ cipherRight0 ^ plainRight0) != guessK5))
  		        {
				 	 guessK4 = 0;
				 	 guessK5 = 0;
					  break;
 		 		}
           }
 	  	   if (guessK4 != 0)
  		   {

		   	  crackedSubkey0 = guessK0;
		   	  crackedSubkey4 = guessK4;
		   	  crackedSubkey5 = guessK5;
		   	  endTime = time(NULL);

		   	  printf("found subkeys : 0x%08lx  0x%08lx  0x%08lx\n", guessK0, guessK4, guessK5);
			  cout<<"  Time to crack round #1 ="<<(endTime - startTime)<<" seconds"<<endl;
		   	  break;

		   }
    }

	cout<<endl<<endl;

	printf("0x%08lx - ", crackedSubkey0); if (crackedSubkey0 == subkey[0]) printf("Subkey 0 : GOOD!\n"); else printf("Subkey 0 : BAD\n");
	printf("0x%08lx - ", crackedSubkey1); if (crackedSubkey1 == subkey[1]) printf("Subkey 1 : GOOD!\n"); else printf("Subkey 1 : BAD\n");
	printf("0x%08lx - ", crackedSubkey2); if (crackedSubkey2 == subkey[2]) printf("Subkey 2 : GOOD!\n"); else printf("Subkey 2 : BAD\n");
	printf("0x%08lx - ", crackedSubkey3); if (crackedSubkey3 == subkey[3]) printf("Subkey 3 : GOOD!\n"); else printf("Subkey 3 : BAD\n");
	printf("0x%08lx - ", crackedSubkey4); if (crackedSubkey4 == subkey[4]) printf("Subkey 4 : GOOD!\n"); else printf("Subkey 4 : BAD\n");
	printf("0x%08lx - ", crackedSubkey5); if (crackedSubkey5 == subkey[5]) printf("Subkey 5 : GOOD!\n"); else printf("Subkey 5 : BAD\n");

	cout<<endl;

	unsigned long fullEndTime = time(NULL);
	cout<<"Total crack time = "<<fullEndTime - fullStartTime<<" seconds"<<endl;


cout<<"FINISHED"<<endl;


    //to stop at the display screen
    while(1){}

    return 0;
}
