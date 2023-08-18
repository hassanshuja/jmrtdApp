﻿using System;
using System.Collections.Generic;
using System.Text;

namespace nl.telin.authep.lib
{
    /// <summary>
    /// The class performs token processing in strings
    /// </summary>
    public class Tokenizer
    {
        /// Position over the string
        private long currentPos = 0;

        /// Include demiliters in the results.
        private bool includeDelims = false;

        /// Char representation of the String to tokenize.
        private char[] chars = null;

        //The tokenizer uses the default delimiter set: the space character, the tab character, the newline character, and the carriage-return character and the form-feed character
        private string delimiters = " \t\n\r\f";

        /// <summary>
        /// Initializes a new class instance with a specified string to process
        /// </summary>
        /// <param name="source">String to tokenize</param>
        public Tokenizer(System.String source)
        {
            this.chars = source.ToCharArray();
        }

        /// <summary>
        /// Initializes a new class instance with a specified string to process
        /// and the specified token delimiters to use
        /// </summary>
        /// <param name="source">String to tokenize</param>
        /// <param name="delimiters">String containing the delimiters</param>
        public Tokenizer(System.String source, System.String delimiters)
            : this(source)
        {
            this.delimiters = delimiters;
        }


        /// <summary>
        /// Initializes a new class instance with a specified string to process, the specified token 
        /// delimiters to use, and whether the delimiters must be included in the results.
        /// </summary>
        /// <param name="source">String to tokenize</param>
        /// <param name="delimiters">String containing the delimiters</param>
        /// <param name="includeDelims">Determines if delimiters are included in the results.</param>
        public Tokenizer(System.String source, System.String delimiters, bool includeDelims)
            : this(source, delimiters)
        {
            this.includeDelims = includeDelims;
        }


        /// <summary>
        /// Returns the next token from the token list
        /// </summary>
        /// <returns>The string value of the token</returns>
        public string NextToken()
        {
            return NextToken(this.delimiters);
        }

        /// <summary>
        /// Returns the next token from the source string, using the provided
        /// token delimiters
        /// </summary>
        /// <param name="delimiters">String containing the delimiters to use</param>
        /// <returns>The string value of the token</returns>
        public string NextToken(string delimiters)
        {
            //According to documentation, the usage of the received delimiters should be temporary (only for this call).
            //However, it seems it is not true, so the following line is necessary.
            this.delimiters = delimiters;

            //at the end 
            if (this.currentPos == this.chars.Length)
                throw new System.ArgumentOutOfRangeException();
            //if over a delimiter and delimiters must be returned
            else if ((System.Array.IndexOf(delimiters.ToCharArray(), chars[this.currentPos]) != -1)
                     && this.includeDelims)
                return "" + this.chars[this.currentPos++];
            //need to get the token wo delimiters.
            else
                return nextToken(delimiters.ToCharArray());
        }

        //Returns the nextToken wo delimiters
        private string nextToken(char[] delimiters)
        {
            string token = "";
            long pos = this.currentPos;

            //skip possible delimiters
            while (System.Array.IndexOf(delimiters, this.chars[currentPos]) != -1)
                //The last one is a delimiter (i.e there is no more tokens)
                if (++this.currentPos == this.chars.Length)
                {
                    this.currentPos = pos;
                    throw new System.ArgumentOutOfRangeException();
                }

            //getting the token
            while (Array.IndexOf(delimiters, this.chars[this.currentPos]) == -1)
            {
                token += this.chars[this.currentPos];
                //the last one is not a delimiter
                if (++this.currentPos == this.chars.Length)
                    break;
            }
            return token;
        }


        /// <summary>
        /// Determines if there are more tokens to return from the source string
        /// </summary>
        /// <returns>True or false, depending if there are more tokens</returns>
        public bool HasMoreTokens()
        {
            //keeping the current pos
            long pos = this.currentPos;

            try
            {
                this.NextToken();
            }
            catch (ArgumentOutOfRangeException)
            {
                return false;
            }
            finally
            {
                this.currentPos = pos;
            }
            return true;
        }

        /// <summary>
        /// Remaining tokens count
        /// </summary>
        public int Count
        {
            get
            {
                //keeping the current pos
                long pos = this.currentPos;
                int i = 0;

                try
                {
                    while (true)
                    {
                        this.NextToken();
                        i++;
                    }
                }
                catch (System.ArgumentOutOfRangeException)
                {
                    this.currentPos = pos;
                    return i;
                }
            }
        }

        /// <summary>
        ///  Performs the same action as NextToken.
        /// </summary>
        public object Current
        {
            get
            {
                return (object)this.NextToken();
            }
        }

        /// <summary>
        /// Performs the same action as HasMoreTokens.
        /// </summary>
        /// <returns>True or false, depending if there are more tokens</returns>
        public bool MoveNext()
        {
            return this.HasMoreTokens();
        }

        /// <summary>
        /// Does nothing.
        /// </summary>
        public void Reset()
        {
            ;
        }		
    }
}
