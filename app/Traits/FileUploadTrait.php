<?php

namespace App\Traits;

trait FileUploadTrait
{
    public function uploadFile($file, $directory)
    {
        return $file->store($directory, 'public');
    }
}
