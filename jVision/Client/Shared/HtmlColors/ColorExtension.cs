﻿using System.Drawing;

namespace jVision.Client.Shared.HtmlColors
{
	public static class ColorExtension
	{
		public static string ToHtmlHex(this Color c)
		{
			return ColorTranslator.ToHtml(c);
		}

		public static string ToHex(this Color c)
		{
			return $"{c.R:X2}{c.G:X2}{c.B:X2}".ToUpper();
		}

		public static string ToRgbString(this Color c)
		{
			return $"{c.R}, {c.G}, {c.B}";
		}
	}
}