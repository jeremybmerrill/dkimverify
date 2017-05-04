require_relative "../dkimverify.rb"

require "minitest/autorun"

class TestDKIMVerify < Minitest::Test
  def setup
  	@verifier = DkimVerify::Verification::Verifier.new(open(File.join(File.dirname(__FILE__), "fixtures", "40178.eml")){|f| f.read })
  end

  def test_that_emails_are_parsed_right
    skip "test this later"  	
    # assert_equal "OHAI!", @meme.i_can_has_cheezburger?
  end

  def test_that_header_kvs_are_parsed_right
    skip "test this later"
    # refute_match /^no/i, @meme.will_it_blend?
  end

  def test_that_canonicalizing_body_simple_works
    skip "test this later"
  end
  def test_that_canonicalizing_headers_simple_works
    skip "test this later"
  end
  def test_that_canonicalizing_body_relaxed_works
    skip "test this later"
  end
  def test_that_canonicalizing_headers_relaxed_works
    skip "test this later"
  end

end

describe DkimVerify::Verification::Verifier do
  # before do
  # 	@verifier = DkimVerify::Verification::Verifier.new(open(File.join(__FILE__, "fixtures", "40178.eml")))
  # end

  describe "when given an invalid input" do
    it "must throw a DKIMVerify error" do
	  	proc { 
		  	@verifier = DkimVerify::Verification::Verifier.new("this is not an email at all")
		}.must_raise DkimVerify::DkimVerifyError
    end
  end

  describe "when given an email that should verify" do
    it "verifies it" do
      @verifier = DkimVerify::Verification::Verifier.new(open(File.join(File.dirname(__FILE__), "fixtures", "40178.eml")){|f| f.read }).verify!.must_be :==, true
    end
  end
  describe "when given an email that shouldn't verify" do
    it "doesn't verify it" do
      proc {
      	@verifier = DkimVerify::Verification::Verifier.new(open(File.join(File.dirname(__FILE__), "fixtures", "40179.eml")){|f| f.read }).verify!
      }.must_raise DkimVerify::Verification::DkimPermFail
    end
  end

end
