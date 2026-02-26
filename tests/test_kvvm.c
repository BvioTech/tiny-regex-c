/**
 * test kvvm audit pattern
 *
 * includes
 *
 *  - password
 *  - credit card
 *  - auth token
 *     - JWT
 *     - oauth token
 *     - api key
 */

#include <stdio.h>
#include <string.h>
#include "re.h"

#define OK ((char *)1)
#define NOK ((char *)0)

char password_pattern_1[] = "\"password\"";
char password_pattern_2[] = "\"passwd\"";
char password_pattern_3[] = "\"pwd\"";
char password_pattern_4[] = "\"passphrase\"";
char password_pattern_5[] = "\"secret\"";

// start with `4`, length 16, split 4 4 4 4
char credit_card_pattern_visa[] = "4\\d\\d\\d-?\\d\\d\\d\\d-?\\d\\d\\d\\d-?\\d\\d\\d\\d";
// start with `51-55` or `2`, length 16, split 4 4 4 4
char credit_card_pattern_mastercard_1[] = "5[1-5]\\d\\d-?\\d\\d\\d\\d-?\\d\\d\\d\\d-?\\d\\d\\d\\d";
char credit_card_pattern_mastercard_2[] = "2\\d\\d\\d-?\\d\\d\\d\\d-?\\d\\d\\d\\d-?\\d\\d\\d\\d";
// start with `35`, length 16, split 4 4 4 4
char credit_card_pattern_jcb[] = "35\\d\\d-?\\d\\d\\d\\d-?\\d\\d\\d\\d-?\\d\\d\\d\\d";
// start with `34` or `37`, length 15, split 4 6 5
char credit_card_pattern_amex[] = "3[47]\\d\\d-?\\d\\d\\d\\d\\d\\d-?\\d\\d\\d\\d\\d";
// start with `62`, length 16, split 4 4 4 4
char credit_card_pattern_unionpay[] = "62\\d\\d-?\\d\\d\\d\\d-?\\d\\d\\d\\d-?\\d\\d\\d\\d";
// start with `30` `36` `38` or `39`, length 14, split 4 6 4
char credit_card_pattern_diners[] = "3[0689]\\d\\d-?\\d\\d\\d\\d\\d\\d-?\\d\\d\\d\\d";

char jwt_pattern[] = "[\\w-]+\\.[\\w-]+\\.[\\w-]+";

char oauth_token_pattern[] = "[Bb]earer\\s[\\w_=-]+";

char api_key_pattern_stripe_1[] = "[sp]k_test_\\w+";
char api_key_pattern_stripe_2[] = "[sp]k_live_\\w+";
char api_key_pattern_github_1[] = "ghp_\\w+";
char api_key_pattern_github_2[] = "github_pat_\\w+";
char api_key_pattern_aws[] = "AKIA[A-Z0-9][A-Z0-9][A-Z0-9][A-Z0-9][A-Z0-9]+";
// "\"(api[_-]?key|token|access[_-]?token|secret|auth[_-]?token|bearer)\""
char api_key_pattern_keyname_1[] = "\"api[_-]?key\"";
char api_key_pattern_keyname_2[] = "\"token\"";
char api_key_pattern_keyname_3[] = "\"access[_-]?token\"";
char api_key_pattern_keyname_4[] = "\"secret\"";
char api_key_pattern_keyname_5[] = "\"auth[_-]?token\"";
char api_key_pattern_keyname_6[] = "\"bearer\"";

char *test_vector[][4] = {
    // password pattern tests
    {OK, password_pattern_1, "{\"password\": \"123\"}", (char *)10},
    {OK, password_pattern_2, "{\"passwd\": \"123\"}", (char *)8},
    {OK, password_pattern_3, "{\"pwd\": \"123\"}", (char *)5},
    {OK, password_pattern_4, "{\"passphrase\": \"123\"}", (char *)12},
    {OK, password_pattern_5, "{\"secret\": \"123\"}", (char *)8},

    // // credit card tests
    {OK, credit_card_pattern_visa, "4111111111111111", (char *)16},
    {OK, credit_card_pattern_visa, "4111-1111-1111-1111", (char *)19},
    {OK, credit_card_pattern_visa, "4000123400001234", (char *)16},
    {NOK, credit_card_pattern_visa, "411111111111111", (char *)0},   // 长度15
    {NOK, credit_card_pattern_visa, "5111111111111111", (char *)0},  // 不以4开头
    {NOK, credit_card_pattern_visa, "4a11111111111111", (char *)0},  // 包含字母
    {NOK, credit_card_pattern_visa, "41-11111111111111", (char *)0}, // 连字符位置错误

    {OK, credit_card_pattern_mastercard_1, "5111111111111111", (char *)16},
    {OK, credit_card_pattern_mastercard_1, "5511111111111111", (char *)16},
    {OK, credit_card_pattern_mastercard_1, "5211-1111-1111-1111", (char *)19},
    {OK, credit_card_pattern_mastercard_1, "5311111111111111", (char *)16},
    {OK, credit_card_pattern_mastercard_1, "5411111111111111", (char *)16},
    {NOK, credit_card_pattern_mastercard_1, "5011111111111111", (char *)0}, // 50开头
    {NOK, credit_card_pattern_mastercard_1, "5611111111111111", (char *)0}, // 56开头
    {NOK, credit_card_pattern_mastercard_1, "511111111111111", (char *)0},  // 长度15

    {OK, credit_card_pattern_mastercard_2, "2111111111111111", (char *)16},
    {OK, credit_card_pattern_mastercard_2, "2111-1111-1111-1111", (char *)19},
    {OK, credit_card_pattern_mastercard_2, "2999999999999999", (char *)16},
    {NOK, credit_card_pattern_mastercard_2, "3111111111111111", (char *)0},  // 不以2开头
    {NOK, credit_card_pattern_mastercard_2, "211111111111111", (char *)0},   // 长度15
    {NOK, credit_card_pattern_mastercard_2, "21-11111111111111", (char *)0}, // 连字符位置错误

    {OK, credit_card_pattern_jcb, "3511111111111111", (char *)16},
    {OK, credit_card_pattern_jcb, "3511-1111-1111-1111", (char *)19},
    {OK, credit_card_pattern_jcb, "3599887766554433", (char *)16},
    {NOK, credit_card_pattern_jcb, "3411111111111111", (char *)0},  // 不以35开头
    {NOK, credit_card_pattern_jcb, "351111111111111", (char *)0},   // 长度15
    {NOK, credit_card_pattern_jcb, "35a1111111111111", (char *)0},  // 包含字母

    {OK, credit_card_pattern_amex, "341111111111111", (char *)15},   // 34开头
    {OK, credit_card_pattern_amex, "371111111111111", (char *)15},   // 37开头
    {OK, credit_card_pattern_amex, "3411-111111-11111", (char *)17}, // 有连字符
    {OK, credit_card_pattern_amex, "3712-345678-90123", (char *)17},
    {NOK, credit_card_pattern_amex, "331111111111111", (char *)0},  // 33开头
    {NOK, credit_card_pattern_amex, "34111111111111", (char *)0},   // 长度14
    {NOK, credit_card_pattern_amex, "34-1111111111111", (char *)0}, // 连字符位置错误（应为4-6-5）

    {OK, credit_card_pattern_unionpay, "6211111111111111", (char *)16},
    {OK, credit_card_pattern_unionpay, "6211-1111-1111-1111", (char *)19},
    {OK, credit_card_pattern_unionpay, "6299887766554433", (char *)16},
    {NOK, credit_card_pattern_unionpay, "6111111111111111", (char *)0},  // 不以62开头
    {NOK, credit_card_pattern_unionpay, "621111111111111", (char *)0},   // 长度15
    {NOK, credit_card_pattern_unionpay, "62-11111111111111", (char *)0}, // 连字符位置错误
    {NOK, credit_card_pattern_unionpay, "62a1111111111111", (char *)0},  // 包含字母

    {OK, credit_card_pattern_diners, "30111111111111", (char *)14},   // 30开头
    {OK, credit_card_pattern_diners, "36111111111111", (char *)14},   // 36开头
    {OK, credit_card_pattern_diners, "38111111111111", (char *)14},   // 38开头
    {OK, credit_card_pattern_diners, "39111111111111", (char *)14},   // 39开头
    {OK, credit_card_pattern_diners, "3011-111111-1111", (char *)16}, // 有连字符
    {OK, credit_card_pattern_diners, "3612-345678-9012", (char *)16},
    {NOK, credit_card_pattern_diners, "31111111111111", (char *)0},  // 31开头
    {NOK, credit_card_pattern_diners, "3011111111111", (char *)0},   // 长度13
    {NOK, credit_card_pattern_diners, "30-111111111111", (char *)0}, // 连字符位置错误

    // // JWT tests
    {OK, jwt_pattern, "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c", (char *)155},
    {OK, jwt_pattern, "abc.def.ghi", (char *)11},
    {NOK, jwt_pattern, "abc.def", (char *)0},
    {OK, jwt_pattern, "a_b.c-d.e_f", (char *)11},
    {NOK, jwt_pattern, "a-b.c+d.e_f", (char *)0},
    {NOK, jwt_pattern, "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ", (char *)0},

    // // OAuth token tests
    {OK, oauth_token_pattern, "Bearer abc123_-=XYZ", (char *)19},
    {OK, oauth_token_pattern, "Bearer abc123", (char *)13},
    {OK, oauth_token_pattern, "Bearer abc123_-=XYZ,extra", (char *)19},
    {OK, oauth_token_pattern, "Bearer abc123_-=XYZ ", (char *)19},
    {NOK, oauth_token_pattern, "Bearer ", (char *)0},
    {OK, oauth_token_pattern, "bearer abc123", (char *)13},
    {NOK, oauth_token_pattern, "Token abc123", (char *)0},

    // // Stripe API key tests
    {OK, api_key_pattern_stripe_1,  "pk_test_123456789012345678901234", (char *)32},
    {OK, api_key_pattern_stripe_1,  "sk_test_abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ", (char *)60},
    {NOK, api_key_pattern_stripe_1, "sk_test_", (char *)0},
    {OK, api_key_pattern_stripe_1,  "sk_test_4eC39HqLyjWDarjtT1zdp7dc", (char *)32},
    {NOK, api_key_pattern_stripe_1, "ak_test_123456789012345678901234", (char *)0},
    {OK, api_key_pattern_stripe_2,  "pk_live_123456789012345678901234", (char *)32},
    {OK, api_key_pattern_stripe_2,  "sk_live_abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ", (char *)60},
    {NOK, api_key_pattern_stripe_2, "sk_live_", (char *)0},
    {OK, api_key_pattern_stripe_2,  "sk_live_4eC39HqLyjWDarjtT1zdp7dc", (char *)32},
    {NOK, api_key_pattern_stripe_2, "ak_live_123456789012345678901234", (char *)0},

    // // GitHub API key tests (ghp_)
    {OK, api_key_pattern_github_1, "ghp_abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMN", (char *)44},
    // // github_pat_
    {OK, api_key_pattern_github_2, "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mmnnnoooppp", (char *)104},

    // // AWS Access Key tests
    {OK, api_key_pattern_aws, "AKIAIOSFODNN7EXAMPLE", (char *)20},
    {OK, api_key_pattern_aws, "AKIA1234567890123456", (char *)20},
    {OK, api_key_pattern_aws, "AKIAIOSFODNN7EXAMPL", (char *)19},
    {NOK, api_key_pattern_aws, "AKIA123", (char *)0},
    {NOK, api_key_pattern_aws, "AKIA", (char *)0},

    // // API key field name tests
    {OK, api_key_pattern_keyname_1, "{\"api_key\":\"123\"}", (char *)9},
    {OK, api_key_pattern_keyname_1, "{\"apikey\":\"123\"}", (char *)8},
    {OK, api_key_pattern_keyname_2, "{\"token\":\"123\"}", (char *)7},
    {OK, api_key_pattern_keyname_3, "{\"access_token\":\"123\"}", (char *)14},
    {OK, api_key_pattern_keyname_3, "{\"accesstoken\":\"123\"}", (char *)13},
    {OK, api_key_pattern_keyname_4, "{\"secret\":\"123\"}", (char *)8},
    {OK, api_key_pattern_keyname_5, "{\"auth_token\":\"123\"}", (char *)12},
    {OK, api_key_pattern_keyname_5, "{\"authtoken\":\"123\"}", (char *)11},
    {OK, api_key_pattern_keyname_6, "{\"bearer\":\"123\"}", (char *)8},
};

void re_print(re_t);

int main()
{
  char *text;
  char *pattern;
  int should_fail;
  int length;
  int correctlen;
  size_t ntests = sizeof(test_vector) / sizeof(*test_vector);
  size_t nfailed = 0;
  size_t i;

  for (i = 0; i < ntests; ++i)
  {
    pattern = test_vector[i][1];
    text = test_vector[i][2];
    should_fail = (test_vector[i][0] == NOK);
    correctlen = (int)(test_vector[i][3]);

    int m = re_match(pattern, text, &length);

    if (should_fail)
    {
      if (m != (-1))
      {
        printf("\n");
        re_print(re_compile(pattern));
        fprintf(stderr, "[%lu/%lu]: pattern '%s' matched '%s' unexpectedly, matched %i chars. \n", (i + 1), ntests, pattern, text, length);
        nfailed += 1;
      }
    }
    else
    {
      if (m == (-1))
      {
        printf("\n");
        re_print(re_compile(pattern));
        fprintf(stderr, "[%lu/%lu]: pattern '%s' didn't match '%s' as expected. \n", (i + 1), ntests, pattern, text);
        nfailed += 1;
      }
      else if (length != correctlen)
      {
        fprintf(stderr, "[%lu/%lu]: pattern '%s' matched '%i' chars of '%s'; expected '%i'. \n", (i + 1), ntests, pattern, length, text, correctlen);
        nfailed += 1;
      }
    }
  }

  // printf("\n");
  printf("%lu/%lu tests succeeded.\n", ntests - nfailed, ntests);
  printf("\n");
  printf("\n");
  printf("\n");

  return nfailed; /* 0 if all tests passed */
}
