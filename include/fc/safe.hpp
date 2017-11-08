#pragma once
#include <fc/exception/exception.hpp>
#include <fc/reflect/reflect.hpp>

#include <limits>

namespace fc {

   /**
    *  This type is designed to provide automatic checks for
    *  integer overflow and default initialization. It will
    *  throw an exception on overflow conditions.
    *
    *  It can only be used on built-in types.  In particular,
    *  safe<uint128_t> is buggy and should not be used.
    *
    *  Implemented using spec from:
    *  https://www.securecoding.cert.org/confluence/display/c/INT32-C.+Ensure+that+operations+on+signed+integers+do+not+result+in+overflow
    */
   
#define Max(T) (std::is_class<T>()?T::max():std::numeric_limits<T>::max())

#define Min(T) (std::is_class<T>()?T::min():std::numeric_limits<T>::min())
   
   template<typename T>
   struct safe
   {
      T value = 0;

      template<typename O>
      safe( O o ):value(o){}
      safe(){}
      safe( const safe& o ):value(o.value){}

      static safe min()
      {
          return  Min(T);
      }
      static safe max()
      {
          return  Max(T);
      }

      friend safe operator + ( const safe& a, const safe& b )
      {
          if( b.value > 0 && a.value > ( Max(T) - b.value) ) FC_CAPTURE_AND_THROW( overflow_exception, (a)(b) );
          if( b.value < 0 && a.value < ( Min(T) - b.value) ) FC_CAPTURE_AND_THROW( underflow_exception, (a)(b) );
          return safe( a.value + b.value );
      }
      friend safe operator - ( const safe& a, const safe& b )
      {
          if( b.value > 0 && a.value < ( Min(T) + b.value) ) FC_CAPTURE_AND_THROW( underflow_exception, (a)(b) );
          if( b.value < 0 && a.value > ( Max(T) + b.value) ) FC_CAPTURE_AND_THROW( overflow_exception, (a)(b) );
          return safe( a.value - b.value );
      }

      friend safe operator * ( const safe& a, const safe& b )
      {
          if( a.value > 0 )
          {
              if( b.value > 0 )
              {
                 auto x=Max(T) / b.value;
                  if( a.value > ( Max(T) / b.value) ) FC_CAPTURE_AND_THROW( overflow_exception, (a)(b) );
              }
              else
              {
                  if( b.value < ( Min(T) / a.value) ) FC_CAPTURE_AND_THROW( underflow_exception, (a)(b) );
              }
          }
          else
          {
              if( b.value > 0 )
              {
                  if( a.value < ( Min(T) / b.value) ) FC_CAPTURE_AND_THROW( underflow_exception, (a)(b) );
              }
              else
              {
                  if( a.value != 0 && b.value < ( Max(T) / a.value) ) FC_CAPTURE_AND_THROW( overflow_exception, (a)(b) );
              }
          }

          return safe( a.value * b.value );
      }

      friend safe operator / ( const safe& a, const safe& b )
      {
          if( b.value == 0 ) FC_CAPTURE_AND_THROW( divide_by_zero_exception, (a)(b) );
          if( a.value ==  Min(T) && b.value == -1 ) FC_CAPTURE_AND_THROW( overflow_exception, (a)(b) );
          return safe( a.value / b.value );
      }
      friend safe operator % ( const safe& a, const safe& b )
      {
          if( b.value == 0 ) FC_CAPTURE_AND_THROW( divide_by_zero_exception, (a)(b) );
          if( a.value ==  Min(T) && b.value == -1 ) FC_CAPTURE_AND_THROW( overflow_exception, (a)(b) );
          return safe( a.value % b.value );
      }

      safe operator - ()const
      {
          if( value ==  Min(T) ) FC_CAPTURE_AND_THROW( overflow_exception, (*this) );
          return safe( -value );
      }

      safe& operator += ( const safe& b )
      {
          value = (*this + b).value;
          return *this;
      }
      safe& operator -= ( const safe& b )
      {
          value = (*this - b).value;
          return *this;
      }
      safe& operator *= ( const safe& b )
      {
          value = (*this * b).value;
          return *this;
      }
      safe& operator /= ( const safe& b )
      {
          value = (*this / b).value;
          return *this;
      }
      safe& operator %= ( const safe& b )
      {
          value = (*this % b).value;
          return *this;
      }

      safe& operator++()
      {
          *this += 1;
          return *this;
      }
      safe operator++( int )
      {
          safe bak = *this;
          *this += 1;
          return bak;
      }

      safe& operator--()
      {
          *this -= 1;
          return *this;
      }
      safe operator--( int )
      {
          safe bak = *this;
          *this -= 1;
          return bak;
      }

      friend bool operator == ( const safe& a, const safe& b )
      {
          return a.value == b.value;
      }
      friend bool operator == ( const safe& a, const T& b )
      {
          return a.value == b;
      }
      friend bool operator == ( const T& a, const safe& b )
      {
          return a == b.value;
      }

      friend bool operator < ( const safe& a, const safe& b )
      {
          return a.value < b.value;
      }
      friend bool operator < ( const safe& a, const T& b )
      {
          return a.value < b;
      }
      friend bool operator < ( const T& a, const safe& b )
      {
          return a < b.value;
      }

      friend bool operator > ( const safe& a, const safe& b )
      {
          return a.value > b.value;
      }
      friend bool operator > ( const safe& a, const T& b )
      {
          return a.value > b;
      }
      friend bool operator > ( const T& a, const safe& b )
      {
          return a > b.value;
      }

      friend bool operator != ( const safe& a, const safe& b )
      {
          return !(a == b);
      }
      friend bool operator != ( const safe& a, const T& b )
      {
          return !(a == b);
      }
      friend bool operator != ( const T& a, const safe& b )
      {
          return !(a == b);
      }

      friend bool operator <= ( const safe& a, const safe& b )
      {
          return !(a > b);
      }
      friend bool operator <= ( const safe& a, const T& b )
      {
          return !(a > b);
      }
      friend bool operator <= ( const T& a, const safe& b )
      {
          return !(a > b);
      }

      friend bool operator >= ( const safe& a, const safe& b )
      {
          return !(a < b);
      }
      friend bool operator >= ( const safe& a, const T& b )
      {
          return !(a < b);
      }
      friend bool operator >= ( const T& a, const safe& b )
      {
          return !(a < b);
      }
   };

}

FC_REFLECT_TEMPLATE( (typename T), safe<T>, (value) )
