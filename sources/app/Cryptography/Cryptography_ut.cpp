/*
 * Cryptography_ut.cpp
 *
 *  Created on: 01.09.2016
 *      Author: tobias
 */

#include "unittest.h"
#include <stdint.h>
#include <cmath>
#include <stdio.h>

#include "Cryptography.h"

#ifndef PMD_CRYPTO_LIBRARY
	#define PMD_CRYPTO_LIBRARY
	#include "crypto.h"
#endif

/**********Test data**********/


/**********Tests**********/
/*
 * @brief 	Test dummy
 * @param  	None
 * @retval 	Amount of errors
 */
int ut_Test_dummy(){
    TestCaseBegin();

    CHECK(true);

    TestCaseEnd();
}

int main(int argc, const char* argv[]){
    UnitTestMainBegin();

    RunTest(true, ut_Test_dummy);

    UnitTestMainEnd();
}
