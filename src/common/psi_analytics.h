#pragma once
//
// \author Oleksandr Tkachenko
// \email tkachenko@encrypto.cs.tu-darmstadt.de
// \organization Cryptography and Privacy Engineering Group (ENCRYPTO)
// \TU Darmstadt, Computer Science department
//
// \copyright The MIT License. Copyright Oleksandr Tkachenko
//
// Permission is hereby granted, free of charge, to any person obtaining
// a copy of this software and associated documentation files (the "Software"),
// to deal in the Software without restriction, including without limitation
// the rights to use, copy, modify, merge, publish, distribute, sublicense,
// and/or sell copies of the Software, and to permit persons to whom the Software
// is furnished to do so, subject to the following conditions:
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
// INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR
// A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
// HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
// OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE
// OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

#include "abycore/aby/abyparty.h"
#include "abycore/circuit/share.h"

#include "helpers.h"
#include "psi_analytics_context.h"

#include "cryptoTools/Common/Defines.h"
#include "cryptoTools/Network/Channel.h"
#include "libOTe/Base/BaseOT.h"
#include "libOTe/TwoChooseOne/IknpOtExtReceiver.h"
#include "libOTe/TwoChooseOne/IknpOtExtSender.h"

#include <vector>

using namespace osuCrypto;

namespace ENCRYPTO {

void PSI(const std::vector<std::uint64_t> &inputs, PsiAnalyticsContext &context, std::vector<uint64_t> &outputs);

// void PSIpayload(const std::vector<std::uint64_t> &inputs, std::vector<std::vector<uint32_t>> &weights, PsiAnalyticsContext &context, std::vector<bool> &equaltags);

void PSIpayload(const std::vector<std::uint64_t> &inputs, std::vector<std::vector<uint32_t>> &weights, 
                PsiAnalyticsContext &context, std::vector<int32_t> &orders, std::vector<bool> &equaltags);

void PSIsharedpayload(const std::vector<std::uint64_t> inputs, std::vector<std::vector<uint32_t>> &weights, 
                      PsiAnalyticsContext &context, std::vector<int32_t> &orders, std::vector<bool> &equaltags);

void PSIsharedpayload(const std::vector<std::uint64_t> inputs, std::vector<std::vector<uint32_t>> &weights, 
                      PsiAnalyticsContext &context, std::vector<int32_t> &orders, std::vector<uint32_t> &perm, std::vector<bool> &equaltags);

void oblivExtTranfer(std::vector<uint32_t> m0, std::vector<uint32_t> m1, std::vector<bool> tag, std::vector<uint32_t> &mr, PsiAnalyticsContext &context);

uint64_t run_psi_analytics(const std::vector<std::uint64_t> &inputs, PsiAnalyticsContext &context);

std::vector<uint64_t> OpprgPsiClient(const std::vector<uint64_t> &elements, std::vector<int32_t> &orders,
                                     PsiAnalyticsContext &context);

std::vector<uint64_t> OpprgPsiServer(const std::vector<uint64_t> &elements,
                                     PsiAnalyticsContext &context);

void OpprgPsiPayloadClient(const std::vector<uint64_t> &elements, std::vector<uint64_t> &bins, 
                           uint64_t weightlen, std::vector<std::vector<uint32_t>> &weights, 
                           std::vector<int32_t> &orders, PsiAnalyticsContext &context);

void OpprgPsiPayloadServer(const std::vector<uint64_t> &elements, std::vector<uint64_t> &bins, 
                           uint64_t weightlen, std::vector<std::vector<uint32_t>> &weights,
                           PsiAnalyticsContext &context);

void InterpolatePolynomials(std::vector<uint64_t> &polynomials,
                            std::vector<uint64_t> &content_of_bins,
                            const std::vector<std::vector<uint64_t>> &masks,
                            PsiAnalyticsContext &context);

void InterpolatePolynomialsPaddedWithDummies(
    std::vector<uint64_t>::iterator polynomial_offset,
    std::vector<uint64_t>::const_iterator random_value_in_bin,
    std::vector<std::vector<uint64_t>>::const_iterator masks_for_elems_in_bin,
    std::size_t nbins_in_megabin, PsiAnalyticsContext &context);

void InterpolatePolynomials(std::vector<uint64_t> &polynomials,
                            const std::vector<std::vector<uint32_t>> &weights,
                            const std::vector<std::vector<uint64_t>> &masks,
                            PsiAnalyticsContext &context);

void InterpolatePolynomialsPaddedWithDummies(
    std::vector<uint64_t>::iterator polynomial_offset,
    std::vector<std::vector<uint32_t>>::const_iterator weights_in_bin,
    std::vector<std::vector<uint64_t>>::const_iterator masks_for_elems_in_bin,
    std::size_t nbins_in_megabin, PsiAnalyticsContext &context);


std::unique_ptr<CSocket> EstablishConnection(const std::string &address, uint16_t port,
                                             e_role role);

std::size_t PlainIntersectionSize(std::vector<std::uint64_t> v1, std::vector<std::uint64_t> v2);

void PrintTimings(const PsiAnalyticsContext &context);
}