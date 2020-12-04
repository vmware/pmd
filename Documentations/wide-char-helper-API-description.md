
This function calculates the length of wide char string.

IN: InputString (wide char string)

This function calculates the length of wide char string.
function PMDWC16StringNumChars (InputString)
{
    length=0
    for every 16-bit character in InputString
      Increment length by 1
    return length
}

This function converts char string with UTF-8 encoding to
wide char string with UCS-2LE encoding.

OUT: OutputString (wide char string)
IN: InputString (char string)

function PMDConvertStringToWC16 (OutputString, InputString)
{
    conv_desc = iconv_open("UCS-2LE", "")
    If conv_desc equals ((iconv_t) -1):
        return with error

    Allocate destination buffer:
        Calculate destination size "OutputSize" from the InputString and allocate OutputString.

    Calculate InputSize from InputString.

    nconv = iconv(conv_desc, InputString, InputSize, OutputString, OutputSize)
    If nconv equals -1:
        Deallocate OutputString
        return with error
}

This function converts wide char string with UCS-2LE encoding to
char string with UTF-8 encoding.

OUT: OutputString (char string)
IN: InputString (wide char string)

function PMDConvertWC16ToString (OutputString, InputString)
{
    conv_desc = iconv_open("", "UCS-2LE")
    If conv_desc equals ((iconv_t) -1):
        return with error

    Allocate destination buffer:
        Calculate destination size "OutputSize" from the InputString and allocate OutputString.

    Calculate InputSize from InputString.

    nconv = iconv(conv_desc, InputString, InputSize, OutputString, OutputSize)
    If nconv equals -1:
        Deallocate OutputString
        return with error
}
