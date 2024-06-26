<?php

/**
 * Joomla! Content Management System
 *
 * @copyright  (C) 2006 Open Source Matters, Inc. <https://www.joomla.org>
 * @license    GNU General Public License version 2 or later; see LICENSE.txt
 */

namespace Joomla\CMS\Utility;

use Joomla\CMS\HTML\HTMLHelper;

// phpcs:disable PSR1.Files.SideEffects
\defined('_JEXEC') or die;
// phpcs:enable PSR1.Files.SideEffects

/**
 * JUtility is a utility functions class
 *
 * @since  1.7.0
 */
class Utility
{
    /**
     * Method to extract key/value pairs out of a string with XML style attributes
     *
     * @param   string  $string  String containing XML style attributes
     *
     * @return  array  Key/Value pairs for the attributes
     *
     * @since   1.7.0
     */
    public static function parseAttributes($string)
    {
        $attr     = [];
        $retarray = [];

        // Let's grab all the key/value pairs using a regular expression
        preg_match_all('/([\w:-]+)[\s]?=[\s]?"([^"]*)"/i', $string, $attr);

        if (\is_array($attr)) {
            $numPairs = \count($attr[1]);

            for ($i = 0; $i < $numPairs; $i++) {
                $retarray[$attr[1][$i]] = $attr[2][$i];
            }
        }

        return $retarray;
    }

    /**
     * Method to get the maximum allowed file size for the HTTP uploads based on the active PHP configuration
     *
     * @param   mixed  $custom  A custom upper limit, if the PHP settings are all above this then this will be used
     *
     * @return  mixed  Size in number of bytes
     *
     * @since   3.7.0
     */
    public static function getMaxUploadSize($custom = null)
    {
        $sizes = [];

        if ($custom) {
            $custom = HTMLHelper::_('number.bytes', $custom, '');

            if ($custom > 0) {
                $sizes[] = $custom;
            }
        }

        /*
         * Read INI settings which affects upload size limits
         * and Convert each into number of bytes so that we can compare
         */
        $sizes[] = HTMLHelper::_('number.bytes', \ini_get('post_max_size'), '');
        $sizes[] = HTMLHelper::_('number.bytes', \ini_get('upload_max_filesize'), '');

        // The minimum of these is the limiting factor
        return min($sizes);
    }
}
