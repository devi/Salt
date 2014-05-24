<?php

class GeCached {

	public $YplusX;
	public $YminusX;
	public $Z;
	public $T2d;

	function __construct() {
		$this->YplusX = new SplFixedArray(10);
		$this->YminusX = new SplFixedArray(10);
		$this->Z = new SplFixedArray(10);
		$this->T2d = new SplFixedArray(10);
	}

}
