<?php

class GeProjective {

	public $X;
	public $Y;
	public $Z;

	function __construct(){
		$this->X = new SplFixedArray(10);
		$this->Y = new SplFixedArray(10);
		$this->Z = new SplFixedArray(10);
	}
}
