use rand::Rng;

/***** Ning wrote this **/
struct LPNOracl {
	dimension: usize,
	secret : Vec<i64>,
	prime: i64,
	error_rate: Vec<f64>,
}

impl LPNOracl {
//	assert_eq!(error_rate.len(), prime);
//	assert_eq!(a.iter().sum(), 1);

	fn generate_one(& self) -> (Vec<i64>, i64) {
		let mut rng = rand::thread_rng();
		let mut a = Vec::with_capacity(self.dimension);
		let mut sum : i64 = 0;
		for i in 1..self.dimension { 
			let r = rng.gen_range(0, self.prime);
			a.push(r);
			sum = (sum + (r * self.secret[i-1] % self.prime) )% self.prime;
		}
		

		let error_loc = rng.gen_range(0.0, 1.0);
		let mut error :i64 = 0;
		let mut counter = 0;

		let mut add : f64 = self.error_rate[0];


		while error_loc > add  { 
			add = add + self.error_rate[counter];
			error = error + 1;
			counter = counter+1;
		}

	   (a, (error + sum)% self.prime)
	}

	
	fn generate_matrix (& self, k : usize) -> (Vec<Vec<i64>>, Vec<i64>) {
		let mut A = Vec::with_capacity(k);
		let mut E = Vec::with_capacity(k);
		for _i in 1..k {		
           let tmp = self.generate_one();
           A.push(tmp.0);
           E.push(tmp.1);
		}

		(A,E)
	}

	// add code here
}
fn  main() {
	let test = LPNOracl{dimension: 5, secret:[0,1,1,0,1].to_vec(), prime: 2, error_rate: [0.5,0.2, 0.1].to_vec()};
	//let (R, error) = test.generate_r();
	println!("{:?}", test.generate_matrix(180));
}
/*************** */
// add code here
