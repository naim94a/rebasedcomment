# Rebased Comment
This plugin rebases comments when you rebase your IDA database.

The plugin will search for hexadecimal numbers that are within range of your program's segments, and fix your comments after every rebase.

Targeting support for IDA 7.0+.

## Installing
Copy `rebased_comment.py` to either `%IDA_INSTALL_DIR%\plugins` or to `%AppData%\Hex-Rays\IDA Pro\plugins`

<table>
    <tr>
        <td>

![Pseudocode Before Rebase](.github/1-before.png "Pseudocode Before Rebase")
        </td>
        <td>
![Rebasing](.github/2-rebasing.png "Rebasing")
        </td>
        <td>
![Pseudocode After Rebase](.github/3-after.png "Pseudocode After Rebase")
        </td>
    </tr>
</table>
