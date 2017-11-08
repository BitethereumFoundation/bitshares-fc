#include <fc/real128.hpp>
#include <boost/test/unit_test.hpp>
#include <fc/log/logger.hpp>
#include <fc/safe.hpp>
#include <iostream>

BOOST_AUTO_TEST_SUITE(fc)

using std::string;
using fc::uint128;
using s_uint128=fc::safe<uint128>;
BOOST_AUTO_TEST_CASE(add_over_flow)
{
   try{
      s_uint128 a=uint128::max();
      s_uint128 b=100;

      auto res=b+a;
   }
   catch(overflow_exception e){
      std::cout<<"add_over_flow"<<std::endl;
   }
   
}
BOOST_AUTO_TEST_CASE(mul_over_flow)
{
   try{
      s_uint128 a=uint128::max();
      s_uint128 b=100;
      
      auto res=b*a;
   }
   catch(overflow_exception e){
      std::cout<<"mul_over_flow"<<std::endl;
   }
   
}
BOOST_AUTO_TEST_CASE(div_over_flow)
{
   try{
      s_uint128 a=uint128::max();
      s_uint128 b=0;
      
      auto res=a/b;
   }
   catch(overflow_exception e){
      std::cout<<"div_over_flow"<<std::endl;
   }
   catch(divide_by_zero_exception e){
      std::cout<<"divide_by_zero_exception"<<std::endl;
   }
}

BOOST_AUTO_TEST_SUITE_END()
