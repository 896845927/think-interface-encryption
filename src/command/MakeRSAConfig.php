<?php
/**
 * Created by PhpStorm.
 * User: mac
 * Date: 2017/4/19
 * Time: 16:00
 */

namespace mrmiao\encryption\command;


use think\console\Command;
use mrmiao\encryption\RSACrypt;
use think\console\Input;
use think\console\Output;


class MakeRSAConfig extends Command
{
    protected function configure()
    {
        $this->setName('MakeRSAConfig')->setDescription('Make RSA Config For Interfaces Crypt');
    }

    protected function execute(Input $input, Output $output)
    {
        RSACrypt::makeRSAKey();
        sleep(5);
        $tips = file_exists(RSACrypt::rsa_config_path) ? 'Success To Make RSA Config!':'Fail To Make RSA Config!';

        $output->writeln($tips);
    }
}