/*
 *  X.509 test certificates
 *
 *  Copyright (C) 2006-2010, Brainspark B.V.
 *
 *  This file is part of PolarSSL (http://www.polarssl.org)
 *  Lead Maintainer: Paul Bakker <polarssl_maintainer at polarssl.org>
 *
 *  All rights reserved.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "polarssl/config.h"

#if defined(POLARSSL_CERTS_C)

const char test_ca_crt[] =
"-----BEGIN CERTIFICATE-----\r\n"
"MIIDhzCCAm+gAwIBAgIBADANBgkqhkiG9w0BAQUFADA7MQswCQYDVQQGEwJOTDER\r\n"
"MA8GA1UEChMIUG9sYXJTU0wxGTAXBgNVBAMTEFBvbGFyU1NMIFRlc3QgQ0EwHhcN\r\n"
"MDkwMjA5MjExMjI1WhcNMTkwMjEwMjExMjI1WjA7MQswCQYDVQQGEwJOTDERMA8G\r\n"
"A1UEChMIUG9sYXJTU0wxGTAXBgNVBAMTEFBvbGFyU1NMIFRlc3QgQ0EwggEiMA0G\r\n"
"CSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCwx0R6mZDvJbXcDZ+VFB+xpnewuZ/X\r\n"
"qf62aJjlUE0znqHTvx77cbPgNap54A/Qbyc6jLMrAWn0mCZHt7pAMNYVLwzkmr87\r\n"
"HuCXtq6Z06KJBeaCP1vtjT26zoum+ecNioktDwcDUkBrrPohnCjy4GNu3UVoxjec\r\n"
"dbx4dJzh8+q0KtWm+KPmor5MWjGywB0SgPszviqMqAnBBQ4LcS77e67SvMBb9TpZ\r\n"
"06I61vSf5VXENw9JRT2qiGp7sbAzgg8HF5RWr6/hXx/SwD/1TRbhtpkoRkNn4F9j\r\n"
"okTBJoQBiXPIU6Ak2iCXCAmO1XdDHjptkkBVhxJcjXlO8I2pZdGeYOfrAgMBAAGj\r\n"
"gZUwgZIwDAYDVR0TBAUwAwEB/zAdBgNVHQ4EFgQUzyIxJ5HYwlT/HtrZ7orFiTKt\r\n"
"DCEwYwYDVR0jBFwwWoAUzyIxJ5HYwlT/HtrZ7orFiTKtDCGhP6Q9MDsxCzAJBgNV\r\n"
"BAYTAk5MMREwDwYDVQQKEwhQb2xhclNTTDEZMBcGA1UEAxMQUG9sYXJTU0wgVGVz\r\n"
"dCBDQYIBADANBgkqhkiG9w0BAQUFAAOCAQEAHBWXOUEAB6MHOjCCy54ByAnz6V9A\r\n"
"/DH1gZhsIaWIWV+YXE2cbE71C5vEBOEWb1kITVf+Dk9TwhBs0A0d57mEeR+UlKmE\r\n"
"g/jJLxxP35IZHmYQjjfVfBTv2cXIyLLBHrfqtsq6aMRjcunqO5YfECcaLVIPaHvq\r\n"
"gAXvfbb3UOiE81c4DWpZmMj7yVYfofr5lCmATJcAja1AYWjOzX1j7OPQGFuslfiV\r\n"
"qCTyUPLyjVfo46qGjP2KnlwCe4WfN4dwdbQUPR52SQ/vau+Vo6yvUaxgTGnPqhM/\r\n"
"oX3Yn5p+NZy1aXBoac1KKEu3jzHuB9eS9VRdtcl44abmFTf33T04R0Sx4g==\r\n"
"-----END CERTIFICATE-----\r\n";

const char test_ca_key[] =
"-----BEGIN RSA PRIVATE KEY-----\r\n"
"Proc-Type: 4,ENCRYPTED\r\n"
"DEK-Info: DES-EDE3-CBC,EB254D9A7718A8E2\r\n"
"\r\n"
"IOUSKEqvYM6tDkyyoAIxiDjZ/lzwCJAbONOxPnvNWL1bxMNYOMcwJxTh7P/EoC6Z\r\n"
"L+ubHlAAUystPRi+h63aZh8qBEai1KOixy5PjqbEKYczagBi5kTIyhCFwwiTiKzB\r\n"
"ygfFjC69wpkgWufKKJQ5skCYF8Pc7RlwKQeAnoPx/3xOFJUK3AHjHAbUhYWrDrqE\r\n"
"CywZYdnaGc9TiXNPcGmwLlgBLjp2zUOS2+lSt+rOjVh3BcaK9z1PRZSXsp20zC8D\r\n"
"1V3gRpbMPly+6BTOrxNuiiQzPK66Mn5g6BCyheanY3ArkM9PVZHmdFe4hvj/cu1L\r\n"
"Ps82XShxEF1IZ1XtqH3gtsJdpAJ7lp6f7/tvjDOokfw+tId3omT7iJJtRKBqYV/u\r\n"
"ujalWa4BU6Ek7yzexBfAe3C82xcn3TDoyXTCdJ3Jgz51cKO+22wTn/CsKh7excBM\r\n"
"ecl0hwhJumunc+Ftmf81qAAZuN4EPF/SxpwQgfBypZ+OqTWBTAvmIwg5dMq2U8Mj\r\n"
"iIXphhA7xbXiMS/yL+aK0vo8GbWVE7Qpwo1BiMfhxc2wxv/W8UpHH2O2WoWTfhUk\r\n"
"wpK2Nm9jteU3SHg76plc5Qf6JqiF7wVuW6mrs8hut0s+q352waAHkOocVA/3xy2A\r\n"
"qL99o/EkzniepORBFhHAJmYx9BolsVP5GQzokfRZkCkLRDm5b7rjx8J1kbWkiy7o\r\n"
"NqyLVfvOjdDBi8cgU1g1K1BVukCD3bL1TNFjfT55xccCYrsosLb7BJFOX8c38DKF\r\n"
"mXV9fQALqna0SKXoMRdU45JMVYQUp8CoLxWq9cCktzI7BCb0cWkTCwhgW3gOwSlO\r\n"
"zDXXzX9iJhb8ZTYIw53Fbi8+shG3DMoixqv8GvFqU3MmxeLEjde+eFHn/kdDugxF\r\n"
"CM6GLRJTf7URUr/H7ILLRxfgrbAk8XlT9CA8ykK+GKIbat0Q8NchW3k2PPNHo+s0\r\n"
"ya65JH6GfDWP29lM1WFxMC0e6Zxjs/ArId2IWCKXLiEjEnzcuAhYZ9d/e6nPbuSQ\r\n"
"oFEA1OfzGcmHJxWMuSX+boF02K/3Eun+fTQjUmD13qQza36MZVRfhlmcg/ztQy4R\r\n"
"JSwr/wJUu/gZql1T+S4sWBq/TZEW7TaAcBs/TE4mqHHrJH2jKmwPswvl58RE2GKS\r\n"
"JHa3CIpAiyqh09dSOsVS+inEISLgRoKQKHuscL0NhRYxB1Nv1sY5OTU8up2fRe4l\r\n"
"LUYwJ57/pEb2//W2XQRW3nUdV5kYTOdIZPaK4T+diK5LhpA2QydXx5aC9GBLEr7r\r\n"
"E+jO7IOJeESxOwjnreYJR2mNgT7QYch227iichheQ0OKRB+vKqnG/6uelH2QH4vJ\r\n"
"NhvEtLZfyrpC3/dEClbDA9akSxOEyzSx1B/t6K43qZe2IZejLGW8nhsi2ZPDxHjz\r\n"
"qrBef1sd91ySRAevsdsGHzCBiC8Ht0H4G76BLj3s611ww8vsOapJlpH2FrFKQo8R\r\n"
"LAdnwehGccL2rJtq1cb9nxwe1xKUQ2K6iew9ITImDup6q0YA9dvFLtoZAtfxMf4R\r\n"
"7qq3iAZUX0ZftEsM6sioiDhI/HBkUQOQd/2oxaYcEc480cMxf1DueA==\r\n"
"-----END RSA PRIVATE KEY-----\r\n";

const char test_ca_pwd[] = "PolarSSLTest";

const char test_srv_crt[] =
"-----BEGIN CERTIFICATE-----\r\n"
"MIIDNzCCAh+gAwIBAgIBCTANBgkqhkiG9w0BAQUFADA7MQswCQYDVQQGEwJOTDER\r\n"
"MA8GA1UEChMIUG9sYXJTU0wxGTAXBgNVBAMTEFBvbGFyU1NMIFRlc3QgQ0EwHhcN\r\n"
"MDkwMjEwMjIxNTEyWhcNMTEwMjEwMjIxNTEyWjA0MQswCQYDVQQGEwJOTDERMA8G\r\n"
"A1UEChMIUG9sYXJTU0wxEjAQBgNVBAMTCWxvY2FsaG9zdDCCASIwDQYJKoZIhvcN\r\n"
"AQEBBQADggEPADCCAQoCggEBALAZHUNK4fFngHtEPyW5EPDxrK9Z+1zj5zJJ87eg\r\n"
"wZAngwQsCxv4PR7YwkBnekrAzatRdzTurqwJa3rLICOzRLF+eKCVUFk2lwRXmnZl\r\n"
"4Ah6CV5hFlnCNevgof2S9dV2w1fzZBkl/6njSFrJt613xYEkLceZ1aUVEmdpACrN\r\n"
"Tk9GQFF4NrUmFZxznNy9+f6sYtwKyKCeqgbp5ZTCvS9G1FQI19aYaR/eY/wJcPKZ\r\n"
"yGMn9wCWHq3D7s6A6HXOUGtsScjEkgSgJXwZbtbgQ0Uq1ypESgO5chekxwG5ToiM\r\n"
"gmMPu8KJmIaObdVeuwu/jNBvlxU5/hHJy97FWyxHZQcgts8CAwEAAaNNMEswCQYD\r\n"
"VR0TBAIwADAdBgNVHQ4EFgQUkgyLP+nT7m8II2IL0Wj9rKYRj18wHwYDVR0jBBgw\r\n"
"FoAUzyIxJ5HYwlT/HtrZ7orFiTKtDCEwDQYJKoZIhvcNAQEFBQADggEBAGlRaNdC\r\n"
"zAy6fShrCjZ1gc5Wp5qEgPdpFDNWHPC0faE3U/F77ExBgb7UPO0BY2GkeCz5wwPS\r\n"
"qwdbIrZ7Y2r5JPlP2JdxTYL0GlkgK5qxy4hl+pO7qvTnUDHQyLHguMymX37/VCXe\r\n"
"id8Sxf4PDsAUuz+Xt7Vor6sFc21i0MQrqy3CvC/TvgvnVYolwqwc9kCIjyGMvSHb\r\n"
"uZ+3s0Rby4zMpQj37vkfkr0P9S7Bc2yYep1Lk06x7H63S3/TxCwNAf66Z2Nqpewp\r\n"
"vQA6RrVDW/gnlOV7ooCalht7S3P7O8Yi3BF+J6aVvjsQ3uqBbTtx3wcTnCwjpifW\r\n"
"Brn4x0KTWpIPMpc=\r\n"
"-----END CERTIFICATE-----\r\n";

const char test_srv_key[] =
"-----BEGIN RSA PRIVATE KEY-----\r\n"
"MIIEowIBAAKCAQEAsBkdQ0rh8WeAe0Q/JbkQ8PGsr1n7XOPnMknzt6DBkCeDBCwL\r\n"
"G/g9HtjCQGd6SsDNq1F3NO6urAlressgI7NEsX54oJVQWTaXBFeadmXgCHoJXmEW\r\n"
"WcI16+Ch/ZL11XbDV/NkGSX/qeNIWsm3rXfFgSQtx5nVpRUSZ2kAKs1OT0ZAUXg2\r\n"
"tSYVnHOc3L35/qxi3ArIoJ6qBunllMK9L0bUVAjX1phpH95j/Alw8pnIYyf3AJYe\r\n"
"rcPuzoDodc5Qa2xJyMSSBKAlfBlu1uBDRSrXKkRKA7lyF6THAblOiIyCYw+7womY\r\n"
"ho5t1V67C7+M0G+XFTn+EcnL3sVbLEdlByC2zwIDAQABAoIBAF1B/5hKiNuCV61w\r\n"
"GA0PNCSVqED440BvRVoBhftCPB/ufNjxxjRaw2uZmU3oPwBlmMXYj8vNd12OY4gV\r\n"
"GIEvh/qDorhQOsv0OAfJqPh4vStgDaQYwHBqhInVXZRfhqc0jQD/2Yvj7sB2qDPE\r\n"
"Teyk2Eiq8z+YfWc+gI+ZMMh6D7W0+mukxeBuhF/+W1p5lPiLpTilJ9QwveVzeH3/\r\n"
"Wn8V5DNKtHXrBXoygrXfzqZWiOWZUruSgZFSgRhspGT9R7fSy1HogUykJE62h6ei\r\n"
"wMvi9AdQxLEBadwMZjCuOLU1TnymHMX5GMno8Zq7TISX7PfKA7fj5xIuueP1kyFg\r\n"
"UOb7VPkCgYEA3mx/VLBIFteCwSd1zv5bGVUk/O0HXNKqd3WUjgtacxNIYVjqostL\r\n"
"CSyQGClNAHvVS/1ba38eAhY7BKazwX/kPJ3x+lo0tgCZQ5uqo/4amI5OJNlWTH1O\r\n"
"7Xw5woyyjI84nJ1rtUSjG9/SxMpK21ZeTNvl2/kYVEt9AsmQLu6ogrUCgYEAyq5f\r\n"
"lTulZJd4NpjLz+gCSqdA5qaoGJ5x+J49uMgAGAthKLD5vrWV1XEI6t4bOhku69sp\r\n"
"MhDmauq6HYlbvhEfkaDXKBwHis/LkGCrWQ2TlTWRo6iqCfgGGSdoEOd04Z/3tpbN\r\n"
"9JVwpUJU+qjz/BZnF3Kx4gNKGy95W7wUlRyIMfMCgYAxLxTJCWIniuhjBfLLHvvO\r\n"
"EkHnnBJwuDTxzZJYBrKtl6n9vMfFz+Z71NrYPOnGHZwA/bllf+qG05uhX6uIMlup\r\n"
"+9MyZRga1u8NQDLvqJUA/xbQly66I0t8wGeVWb9xzYnbOARFRTQ8SbY1xfXfoq2f\r\n"
"mVCu39o9aaPvJds4RZYFsQKBgQCTY16qvSc3EVcgDNkZpZQVCa+Oi17uGDq1Gw2z\r\n"
"U+2Njqjm2FulLZN6FarwcPfHtgyDA2rft5533Z3eYMbQXs9gLWCJEGkDrrxPj5zL\r\n"
"M65A8SWpp7uPaEe2/wsUT9yVPqj6pIu88vdpleUKKtbSWNA7IvLscovvXQSZixpE\r\n"
"nO0FtQKBgEDDqxchzGIpKfi0sPSdt9TfOZADdI7Tc28U7ktWcVnArtGGyecwatr7\r\n"
"nZUP68MPjezyldQPT0OYQgnIHm6smDbEEGVomIHuIPwFT8bFNX6fCh1NQWzTaNtv\r\n"
"alggV/is0bHz2sGVtWTy0N8jAyFmlDxCWBcqaQ2hVP2910rQgUVd\r\n"
"-----END RSA PRIVATE KEY-----\r\n";

const char test_cli_crt[] =
"-----BEGIN CERTIFICATE-----\r\n"
"MIIDPzCCAiegAwIBAgIBBDANBgkqhkiG9w0BAQUFADA7MQswCQYDVQQGEwJOTDER\r\n"
"MA8GA1UEChMIUG9sYXJTU0wxGTAXBgNVBAMTEFBvbGFyU1NMIFRlc3QgQ0EwHhcN\r\n"
"MDkwMjA5MjExMjM1WhcNMTEwMjA5MjExMjM1WjA8MQswCQYDVQQGEwJOTDERMA8G\r\n"
"A1UEChMIUG9sYXJTU0wxGjAYBgNVBAMTEVBvbGFyU1NMIENsaWVudCAyMIIBIjAN\r\n"
"BgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAodfTDCz/vIWD4rI8wlsV/pJ8Cbh7\r\n"
"3pA5GU1RJhvIvdOfZKtmeS4eLD/YBwnwSTSe997dSme1lryeerxq5BXyRQw9JjIz\r\n"
"p+X+8Rng4x2GMKjksV9gZVZJGFVM7vILO2TOIrQt1hjh9ZYDUZz0/6gmI86aJ+Uh\r\n"
"gxazzKdb4W1nLF7hI7tWKR8u5P/CAUO0uVrkbSunMfvuC9uYSXVTN3UdknXV3Ncs\r\n"
"4ecqxL4V9v9OpDiHy2Z4q026SuCqFRZ0LpvIk5bqv8ZsQFQ527tUTNydU0oAhlvv\r\n"
"/UpZxh645GkBAzvxOgMK1J8mUGCbiz10Ewdu+c3n1uqX4Q+LCJnsxClwMwIDAQAB\r\n"
"o00wSzAJBgNVHRMEAjAAMB0GA1UdDgQWBBSMBjiT2RQGKd/MzXERQzeO8EM4GzAf\r\n"
"BgNVHSMEGDAWgBTPIjEnkdjCVP8e2tnuisWJMq0MITANBgkqhkiG9w0BAQUFAAOC\r\n"
"AQEAZra5syKfgQmS8p8i7N9HPMUY5AGDT2lbEYhzcabvJZXRI+BNmiW71qyoiIbM\r\n"
"Bm6pyUcsBqXcskq2W2xMD/lcvLTo0kp51Sdnnyw471tUtLwTDrpyc1Q3PTn84Rfr\r\n"
"WT7suINW0csyzhMBiGFwjvnOl5VGOLqhd47upIajMBK3EN97dBhFPFeqVNrlxcC1\r\n"
"e01dwMLnDdDyqzZbAqg+H25KqrIFnzWq1ibxXyeil26cVpUeTvtbS09Y93uNVBzl\r\n"
"00p4klj1ol+YY1TX/W0UX0kSmdAy1SrAxpek0fXCndy0bPC6++c+9YZhu4bp5JkK\r\n"
"7e7c+oTqh+DDfnbkF6NYJQeCvw==\r\n"
"-----END CERTIFICATE-----\r\n";

const char test_cli_key[] =
"-----BEGIN RSA PRIVATE KEY-----\r\n"
"MIIEpAIBAAKCAQEAodfTDCz/vIWD4rI8wlsV/pJ8Cbh73pA5GU1RJhvIvdOfZKtm\r\n"
"eS4eLD/YBwnwSTSe997dSme1lryeerxq5BXyRQw9JjIzp+X+8Rng4x2GMKjksV9g\r\n"
"ZVZJGFVM7vILO2TOIrQt1hjh9ZYDUZz0/6gmI86aJ+UhgxazzKdb4W1nLF7hI7tW\r\n"
"KR8u5P/CAUO0uVrkbSunMfvuC9uYSXVTN3UdknXV3Ncs4ecqxL4V9v9OpDiHy2Z4\r\n"
"q026SuCqFRZ0LpvIk5bqv8ZsQFQ527tUTNydU0oAhlvv/UpZxh645GkBAzvxOgMK\r\n"
"1J8mUGCbiz10Ewdu+c3n1uqX4Q+LCJnsxClwMwIDAQABAoIBAQCepSN6QfoF4JMh\r\n"
"ezpYAlWTECCKns69on52MPYk9wNWIMWUNvfiPbTSB1tJuxJRkEVsEIi3UOYN9qMb\r\n"
"COt23ZR43sBqWreME8ZOrOFngB90P3q97BJgA67vLV6Ws6kS9YOjPR/ZSNbml8B1\r\n"
"FfiLS1bnrrQp+09YYr6pFDzawxVpxaCfr6mpfDbXhoBw0NGpf54V4rIm4eNIf9Ro\r\n"
"QS54g/d0thID9OhMrc2NIpfRs4GkebsxOIKZP+uKF6CoS8IujyKjab/Vb3XBSknD\r\n"
"ObmiDx+udh8gRRGSpIG8rgoMcM8JhPAYitjYo3AiRTPTAUb4nSgQVOVxnRRZX8C1\r\n"
"QhvKOntBAoGBANAmX4KzOncoELOZPAZpkBlAhLNEqKT6RrfVokR9JAz3Jqhe+3tF\r\n"
"a0taSHF0aDi7YI5PgRGsV2Bowf81IIS3z2UqHCf+Eo0745jPiY33V+KSQkydJruN\r\n"
"u/n89imdhcIZdvZoxoVB8aRFDarBlzVq/FozqcpbtiGNs2ogbf+xS1dRAoGBAMcM\r\n"
"Swc0S0G2ncec34beGNH9mloyseMVspGhUWy/3rKLLBVf7XtEM4eDMopgMeceWQw9\r\n"
"wZo4Hr9Ip8k3Z4Ue8wV+MxtSLuGaxHGnHVxJtEE9OarhKlvEqHVAeeWvK4Cr0+ip\r\n"
"/zxnWDAA7QulMuWiK0LBEYOvTUXFet4z/l27/rZDAoGAchjWufosziw0G36fnJQ4\r\n"
"3N603t9/4g8evJ5qOEiwfjrsAdcu2r+OtNtkYmyAxLhRkTCbe2iQ7NP/ozkn/hgT\r\n"
"o0yV6oYm/Swa8iSxLhSrJBMwLHboSF7E759uABnMvDzhLOj6CQnAv17qwvMjQ7DF\r\n"
"a1xucfIbwADAnCfyo/o3ZkECgYEApfbGCDe+GAif/fP7HITKxSxjKpniYKmSvoJ3\r\n"
"VemVUeFg3GGjrYfsPy1RUrdqZH6VWPOVHXV1jaCS5d9gXUq07vuOuVUI6esVqH3i\r\n"
"qTR7K3pVPvmHTATpQPqFqNEpwJuEkRZNTpwMl9ntzCvuCDHzSDGa3OWp1GcYT3Wi\r\n"
"vZ0mf+kCgYBEPLnXD1BH7BlzEsMfXCtw28VtTetixcHcZVKwzQ4UH035DFYHch3p\r\n"
"/rABUO+IwxfcHjrvUJyZgHTyzfhtjWV62SsTNrOa1JFhQ+frWxIU5VEA7rVnLeaO\r\n"
"3vMGjy6jnBSaKoktW8ikY+4FHq+t5z63UN3RF367Iz0dWzIVocbxAQ==\r\n"
"-----END RSA PRIVATE KEY-----\r\n";

#endif
