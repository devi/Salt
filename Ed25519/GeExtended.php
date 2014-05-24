<?php

class GeExtended extends GeProjective {

	public $T;

	function __construct(){
		parent::__construct();
		$this->T = new SplFixedArray(10);
	}
}
